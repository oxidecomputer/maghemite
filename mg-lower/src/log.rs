// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

macro_rules! ddm_log {
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM,
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM,
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*;) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM,
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DDM,
        )
    };
}

macro_rules! dpd_log {
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD,
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD,
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*;) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD,
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_DPD,
        )
    };
}

macro_rules! mgl_log {
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP,
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP,
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*;) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP,
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MG_LOWER,
            "module" => crate::MOD_SYNC,
            "unit" => UNIT_EVENT_LOOP,
        )
    };
}

pub(crate) use {ddm_log, dpd_log, mgl_log};
