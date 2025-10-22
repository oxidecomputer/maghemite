// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

macro_rules! rdb_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_RDB,
            "module" => crate::MOD_DB,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_RDB,
            "module" => crate::MOD_DB,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_RDB,
            "module" => crate::MOD_DB,
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_RDB,
            "module" => crate::MOD_DB,
        )
    };
}

pub(crate) use rdb_log;
