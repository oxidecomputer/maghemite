// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    messages::{
        Capability, CapabilityCode, Community, Message, OpenMessage, Prefix,
        UpdateMessage,
    },
    policy::{CheckerResult, ShaperResult},
};
use rhai::{export_module, plugin::*, Module};

macro_rules! create_enum_module {
    ($module:ident : $typ:ty => $($variant:ident),+) => {
        #[rhai::export_module]
        pub mod $module {
            $(
                #[allow(non_upper_case_globals)]
                pub const $variant: $typ = <$typ>::$variant;
            )*
        }
    };
}

create_enum_module! {
    capability_code_module: CapabilityCode =>
        Reserved,
        MultiprotocolExtensions,
        RouteRefresh,
        OutboundRouteFiltering,
        MultipleRoutesToDestination,
        ExtendedNextHopEncoding,
        BGPExtendedMessage,
        BgpSec,
        MultipleLabels,
        BgpRole,
        GracefulRestart,
        FourOctetAs,
        DynamicCapability,
        MultisessionBgp,
        AddPath,
        EnhancedRouteRefresh,
        LongLivedGracefulRestart,
        RoutingPolicyDistribution,
        Fqdn,
        PrestandardRouteRefresh,
        PrestandardOrfAndPd,
        PrestandardOutboundRouteFiltering,
        PrestandardMultisession,
        PrestandardFqdn,
        PrestandardOperationalMessage
}

create_enum_module! {
    checker_result_module: CheckerResult => Accept, Drop
}

// Rhai needs methods to be &mut self and not just &self, so the following
// methods are to accomplish that and a bit of type translation in cases
// where complex rust types would be difficult to deal with in rhai.
impl OpenMessage {
    pub fn rhai_has_capability(&mut self, code: CapabilityCode) -> bool {
        self.has_capability(code)
    }
    pub fn add_four_octet_as(&mut self, asn: i64) {
        let asn = match asn.try_into() {
            Ok(asn) => asn,
            Err(_) => return, //TODO something better?
        };
        self.add_capabilities(&[Capability::FourOctetAs { asn }]);
    }
    pub fn emit(&mut self) -> ShaperResult {
        ShaperResult::Emit(Message::Open(self.clone()))
    }
}

impl UpdateMessage {
    pub fn rhai_has_community(&mut self, community: i64) -> bool {
        // rhai integers are of type i64, so if we get something bigger, the
        // answer is no, as communities out of the 32 bit range are not defined
        let c: u32 = match community.try_into() {
            Ok(c) => c,
            Err(_) => return false,
        };
        self.has_community(Community::from(c))
    }

    pub fn rhai_add_community(&mut self, community: i64) {
        let c: u32 = match community.try_into() {
            Ok(c) => c,
            Err(_) => return, //TODO something better
        };
        self.add_community(Community::from(c));
    }

    pub fn emit(&mut self) -> ShaperResult {
        ShaperResult::Emit(Message::Update(self.clone()))
    }

    pub fn prefix_filter<F>(&mut self, f: F)
    where
        F: Clone + Fn(&Prefix) -> bool,
    {
        self.withdrawn.retain(f.clone());
        self.nlri.retain(f);
    }

    pub fn get_nlri(&mut self) -> Vec<Prefix> {
        self.nlri.clone()
    }

    pub fn set_nlri(&mut self, value: Vec<Prefix>) {
        self.nlri = value;
    }
}

// Create a plugin module with functions constructing the 'ShaperResult' variants
#[export_module]
pub mod shaper_result_module {

    use crate::{messages::Message, policy::ShaperResult};
    use rhai::Dynamic;

    // Constructors for 'ShaperResult' variants
    #[allow(non_upper_case_globals)]
    pub const Drop: ShaperResult = ShaperResult::Drop;

    #[allow(non_snake_case)]
    pub fn Emit(value: Message) -> ShaperResult {
        ShaperResult::Emit(value)
    }

    /// Return the current variant of `ShaperResult`.
    #[rhai_fn(global, get = "enum_type", pure)]
    pub fn get_type(sr: &mut ShaperResult) -> String {
        match sr {
            ShaperResult::Drop => "Drop".to_string(),
            ShaperResult::Emit(_) => "Emit".to_string(),
        }
    }

    /// Return the inner value.
    #[rhai_fn(global, get = "value", pure)]
    pub fn get_value(sr: &mut ShaperResult) -> Dynamic {
        match sr {
            ShaperResult::Drop => Dynamic::UNIT,
            ShaperResult::Emit(x) => Dynamic::from(x.clone()),
        }
    }

    // Access to inner values by position

    /// Return the value kept in the first position of `ShaperResult`.
    #[rhai_fn(global, get = "field_0", pure)]
    pub fn get_field_0(sr: &mut ShaperResult) -> Dynamic {
        match sr {
            ShaperResult::Drop => Dynamic::UNIT,
            ShaperResult::Emit(x) => Dynamic::from(x.clone()),
        }
    }

    // Printing
    #[rhai_fn(global, name = "to_string", name = "to_debug", pure)]
    pub fn to_string(sr: &mut ShaperResult) -> String {
        format!("{sr:?}")
    }

    // '==' and '!=' operators
    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(sr: &mut ShaperResult, sr2: ShaperResult) -> bool {
        sr == &sr2
    }
    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(sr: &mut ShaperResult, sr2: ShaperResult) -> bool {
        sr != &sr2
    }
}

impl Prefix {
    pub fn within_rhai(&mut self, x: &str) -> bool {
        let x: Prefix = match x.parse() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s = self.clone();
        s.within(&x)
    }
}
