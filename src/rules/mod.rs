pub mod wrd101;
pub mod wrd110;
pub mod wrd111;
pub mod wrd112;
pub mod wrd113;
pub mod wrd120;
pub mod wrd201;
pub mod wrd202;
pub mod wrd203;
pub mod wrd301;
pub mod wrd302;
pub mod wrd310;
pub mod wrd320;
pub mod wrd321;
pub mod wrd322;
pub mod wrd323;
pub mod wrd324;
pub mod wrd325;
pub mod wrd326;
pub mod wrd327;
pub mod wrd420;
pub mod wrd421;
pub mod wrd422;
pub mod wrd424;
pub mod wrd510;
pub mod wrd511;
pub mod wrd520;
pub mod wrd521;
pub mod wrd525;
pub mod wrd601;
pub mod wrd602;
pub mod wrd701;
pub mod wrd710;
pub mod wrd711;
pub mod wrd712;
pub mod wrd713;
pub mod wrd714;
pub mod wrd720;
pub mod wrd801;
pub mod wrd810;
pub mod wrd811;
pub mod wrd812;
pub mod wrd820;
pub mod wrd821;
pub mod wrd822;
pub mod wrd823;
pub mod wrd824;
pub mod wrd825;
pub mod wrd826;
pub mod wrd827;
pub mod wrd828;
pub mod wrd831;
pub mod wrd833;

use crate::scanner::Workflow;

pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub remediation: String,
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn severity(&self) -> &str;
    fn description(&self) -> &str;
    fn check(&self, workflow: &Workflow) -> Vec<Finding>;
}

/// Find the 1-based line number of a byte offset in text.
pub fn line_number_at_offset(content: &str, offset: usize) -> usize {
    content[..offset.min(content.len())].matches('\n').count() + 1
}

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(wrd101::Wrd101),
        Box::new(wrd110::Wrd110),
        Box::new(wrd111::Wrd111),
        Box::new(wrd112::Wrd112),
        Box::new(wrd113::Wrd113),
        Box::new(wrd120::Wrd120),
        Box::new(wrd201::Wrd201),
        Box::new(wrd202::Wrd202),
        Box::new(wrd203::Wrd203),
        Box::new(wrd301::Wrd301),
        Box::new(wrd302::Wrd302),
        Box::new(wrd310::Wrd310),
        Box::new(wrd320::Wrd320),
        Box::new(wrd321::Wrd321),
        Box::new(wrd322::Wrd322),
        Box::new(wrd323::Wrd323),
        Box::new(wrd324::Wrd324),
        Box::new(wrd325::Wrd325),
        Box::new(wrd326::Wrd326),
        Box::new(wrd327::Wrd327),
        Box::new(wrd420::Wrd420),
        Box::new(wrd421::Wrd421),
        Box::new(wrd422::Wrd422),
        Box::new(wrd424::Wrd424),
        Box::new(wrd510::Wrd510),
        Box::new(wrd511::Wrd511),
        Box::new(wrd520::Wrd520),
        Box::new(wrd521::Wrd521),
        Box::new(wrd525::Wrd525),
        Box::new(wrd601::Wrd601),
        Box::new(wrd602::Wrd602),
        Box::new(wrd701::Wrd701),
        Box::new(wrd710::Wrd710),
        Box::new(wrd711::Wrd711),
        Box::new(wrd712::Wrd712),
        Box::new(wrd713::Wrd713),
        Box::new(wrd714::Wrd714),
        Box::new(wrd720::Wrd720),
        Box::new(wrd801::Wrd801),
        Box::new(wrd810::Wrd810),
        Box::new(wrd811::Wrd811),
        Box::new(wrd812::Wrd812),
        Box::new(wrd820::Wrd820),
        Box::new(wrd821::Wrd821),
        Box::new(wrd822::Wrd822),
        Box::new(wrd823::Wrd823),
        Box::new(wrd824::Wrd824),
        Box::new(wrd825::Wrd825),
        Box::new(wrd826::Wrd826),
        Box::new(wrd827::Wrd827),
        Box::new(wrd828::Wrd828),
        Box::new(wrd831::Wrd831),
        Box::new(wrd833::Wrd833),
    ]
}
