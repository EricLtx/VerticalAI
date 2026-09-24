//! Egress telemetry: what a launched process is talking to.
//!
//! [`sample`] returns the remote `ip:port` of every established TCP connection
//! owned by a process id — on Windows through `GetExtendedTcpTable`
//! (`TCP_TABLE_OWNER_PID_ALL`, IPv4 and IPv6), elsewhere an empty list, because
//! this is observation and not enforcement and a platform we cannot observe on
//! yet must say nothing rather than guess. [`launch`](crate::launch) samples it
//! every 500 ms into the run record; the kernel writes that record to the
//! ledger as `harness.connections`.
//!
//! What this is not: a firewall. It sees what the process connected to, after
//! the fact, so an auditor can check the harness talked only to the endpoints it
//! should. Blocking egress is the confined-network-namespace work of a later
//! sprint (`contracts/tcb.md`).
//!
//! It reads only the *remote* address of *established* connections owned by the
//! pid: a listening socket has no peer worth recording, and a bound-but-idle one
//! is not egress. Connections owned by a child the process spawned are missed —
//! the table is keyed by the owning pid — which is noted where it matters
//! (`contracts/tcb.md`); Claude Code's native binary owns its own TLS sockets.

/// The remote `ip:port` of every established TCP connection owned by `pid`,
/// deduplicated within this one sample and sorted. Empty on any platform but
/// Windows, and empty on Windows when the process owns no established
/// connection right now.
pub fn sample(pid: u32) -> Vec<String> {
    #[cfg(windows)]
    {
        win::sample(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Vec::new()
    }
}

#[cfg(windows)]
mod win {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// `MIB_TCP_STATE_ESTAB` — the one state that is a live conversation with a
    /// peer. The IpHelper `MIB_TCP_STATE` enum is not pulled in for one integer.
    const ESTABLISHED: u32 = 5;

    pub fn sample(pid: u32) -> Vec<String> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        collect_v4(pid, &mut out);
        collect_v6(pid, &mut out);
        out.into_iter().collect()
    }

    /// Fetch the owner-pid TCP table for `family` into a byte buffer, growing it
    /// once when the OS says it is too small. `None` on any error: telemetry
    /// that cannot be read is reported as nothing seen, never as a failure of
    /// the run it was watching.
    fn table_bytes(family: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        // First call sizes the buffer: a null pointer with a zero size is the
        // documented way to ask how many bytes the table needs right now.
        // SAFETY: `size` outlives the call; a null table pointer with size 0 is
        // the documented probe and writes nothing.
        let probe = unsafe {
            GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
        };
        if WIN32_ERROR(probe) != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` holds `size` bytes and stays alive for the call; `size`
        // is the length the probe asked for.
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        (WIN32_ERROR(rc) == NO_ERROR).then_some(buf)
    }

    fn collect_v4(pid: u32, out: &mut BTreeSet<String>) {
        let Some(buf) = table_bytes(AF_INET.0 as u32) else {
            return;
        };
        // The table is a `dwNumEntries: u32` followed by that many rows.
        // SAFETY: `buf` came from `GetExtendedTcpTable(AF_INET, OWNER_PID_ALL)`,
        // so it begins with `MIB_TCPTABLE_OWNER_PID`; we read only the count and
        // then the rows the count promises, none past the buffer.
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        // `table.table` is a one-element array laid out as the head of the real
        // (variable-length) row array, so its pointer is the row pointer.
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), n) };
        for row in rows {
            if row.dwOwningPid == pid && row.dwState == ESTABLISHED {
                // `dwRemoteAddr` is already in network byte order; the port's
                // low 16 bits are network order too.
                let ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                let port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
                out.insert(format!("{ip}:{port}"));
            }
        }
    }

    fn collect_v6(pid: u32, out: &mut BTreeSet<String>) {
        let Some(buf) = table_bytes(AF_INET6.0 as u32) else {
            return;
        };
        // SAFETY: as `collect_v4`, for the IPv6 table shape.
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), n) };
        for row in rows {
            if row.dwOwningPid == pid && row.dwState == ESTABLISHED {
                let ip = Ipv6Addr::from(row.ucRemoteAddr);
                let port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
                out.insert(format!("[{ip}]:{port}"));
            }
        }
    }
}
