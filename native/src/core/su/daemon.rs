use super::db::RootSettings;
use crate::consts::SELLER_PACKAGE_NAME;
use crate::package::get_package_uid;
use crate::daemon::{AID_ROOT, MagiskD, to_user_id};
use crate::db::DbSettings;
use crate::ffi::{SuPolicy, SuRequest, exec_root_shell};
use crate::socket::IpcRead;
use base::{ResultExt, WriteExt, debug, error, exit_on_error, libc, warn};
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UCred, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[allow(unused_imports)]
use std::os::fd::AsRawFd;

impl Default for SuRequest {
    fn default() -> Self {
        SuRequest {
            target_uid: AID_ROOT,
            target_pid: -1,
            keep_env: false,
            drop_cap: false,
            command: vec![],
            context: "".to_string(),
            gids: vec![],
        }
    }
}

#[derive(Clone)]
pub struct SuInfo {
    pub(super) uid: i32,
    pub(super) eval_uid: i32,
    pub(super) settings: RootSettings,
    cfg: DbSettings,
    timestamp: Instant,
}

impl Default for SuInfo {
    fn default() -> Self {
        SuInfo {
            uid: -1,
            eval_uid: -1,
            settings: Default::default(),
            cfg: Default::default(),
            timestamp: Instant::now(),
        }
    }
}

impl SuInfo {
    fn allow(uid: i32) -> SuInfo {
        let settings = RootSettings {
            policy: SuPolicy::Allow,
            ..Default::default()
        };
        SuInfo {
            uid,
            settings,
            ..Default::default()
        }
    }

    fn deny(uid: i32) -> SuInfo {
        SuInfo {
            uid,
            ..Default::default()
        }
    }

    fn is_fresh(&self) -> bool {
        self.timestamp.elapsed() < Duration::from_secs(3)
    }

    fn refresh(&self) -> SuInfo {
        SuInfo {
            timestamp: Instant::now(),
            ..self.clone()
        }
    }
}

impl MagiskD {
    pub fn su_daemon_handler(&self, mut client: UnixStream, cred: UCred) {
        debug!(
            "su: request from uid=[{}], pid=[{}], client=[{}]",
            cred.uid,
            cred.pid.unwrap_or(-1),
            client.as_raw_fd()
        );

        let mut req = match client.read_decodable::<SuRequest>().log() {
            Ok(req) => req,
            Err(_) => {
                warn!("su: remote process probably died, abort");
                client.write_pod(&SuPolicy::Deny.repr).ok();
                return;
            }
        };

        let info = self.get_su_info(cred.uid as i32);

        // Talk to su manager
        self.notify_app(&cred, &info, &req);

        match info.settings.policy {
            SuPolicy::Restrict => req.drop_cap = true,
            SuPolicy::Allow => {}
            _ => {
                warn!("su: request rejected ({})", info.uid);
                client.write_pod(&SuPolicy::Deny.repr).ok();
                return;
            }
        }

        // At this point, the root access is granted.
        // Fork a child root process and monitor its exit value.
        let child = unsafe { libc::fork() };
        if child == 0 {
            debug!("su: fork handler");

            // Abort upon any error occurred
            exit_on_error(true);

            // ack
            client.write_pod(&0).ok();

            exec_root_shell(
                client.into_raw_fd(),
                cred.pid.unwrap_or(-1),
                &mut req,
                info.cfg.mnt_ns,
            );
            return;
        }
        if child < 0 {
            error!("su: fork failed, abort");
            return;
        }

        // Wait result
        debug!("su: waiting child pid=[{}]", child);
        let mut status = 0;
        let code = unsafe {
            if libc::waitpid(child, &mut status, 0) > 0 {
                libc::WEXITSTATUS(status)
            } else {
                -1
            }
        };
        debug!("su: return code=[{}]", code);
        client.write_pod(&code).ok();
    }

    fn get_su_info(&self, uid: i32) -> Arc<SuInfo> {
        if uid == AID_ROOT {
            return Arc::new(SuInfo::allow(AID_ROOT));
        }

        let cached = self.cached_su_info.load();
        if cached.uid == uid && cached.is_fresh() {
            let info = Arc::new(cached.refresh());
            self.cached_su_info.store(info.clone());
            return info;
        }

        let info = self.build_su_info(uid);
        self.cached_su_info.store(info.clone());
        info
    }

    // Whitelist-only policy: root is granted silently to the manager app and
    // the seller app. Every other uid (including adb shell) is rejected.
    #[cfg(feature = "su-check-db")]
    fn build_su_info(&self, uid: i32) -> Arc<SuInfo> {
        let user = to_user_id(uid);
        let mgr_uid = self.get_manager_uid(user);
        let seller_uid = get_package_uid(user, SELLER_PACKAGE_NAME);
        if (mgr_uid >= 0 && uid == mgr_uid) || (seller_uid >= 0 && uid == seller_uid) {
            Arc::new(SuInfo::allow(uid))
        } else {
            Arc::new(SuInfo::deny(uid))
        }
    }

    #[cfg(not(feature = "su-check-db"))]
    fn build_su_info(&self, uid: i32) -> Arc<SuInfo> {
        Arc::new(SuInfo::allow(uid))
    }
}
