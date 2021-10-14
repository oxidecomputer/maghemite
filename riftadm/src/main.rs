// Copyright 2021 Oxide Computer Company

use anyhow::Result;
use std::time::SystemTime;
use clap::{AppSettings, Clap};
use reqwest;
use std::io::{stdout, Write};
use rift::{
    link::LinkSMState,
};
use std::collections::HashMap;
use tabwriter::TabWriter;
use colored::*;

#[derive(Clap)]
#[clap(
    version = "0.1", 
    author = "Ryan Goodfellow <ryan.goodfellow@oxide.computer>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Opts {
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Status(Status),
    Lsdb(Lsdb),
}


#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Status { }

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Lsdb { }

fn main() {
    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Status(ref s) => {
            match status(&opts, &s) {
                Ok(()) => {}
                Err(e) => println!("{}", e),
            }
        }
        SubCommand::Lsdb(ref l) => {
            match lsdb(&opts, &l) {
                Ok(()) => {}
                Err(e) => println!("{}", e),
            }
        }
    }
}

fn status(_opts: &Opts, _s: &Status) -> Result<()> {

    let mut tw = TabWriter::new(stdout());
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        "Link".dimmed(),
        "Rift State".dimmed(),
        "Link State".dimmed(),
        "Local Address".dimmed(),
        "Peer Address".dimmed(),
        "Last Seen".dimmed(),
        "LIE".dimmed(),
    )?;
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        "----".bright_black(),
        "----------".bright_black(),
        "----------".bright_black(),
        "-------------".bright_black(),
        "------------".bright_black(),
        "---------".bright_black(),
        "---".bright_black(),
    )?;

    let response: HashMap<String, LinkSMState> = 
        reqwest::blocking::get("http://localhost:7000/links")?.json()?;

    for (link_name, info) in &response {

        write!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            link_name,
            color_rift_state(info.current),
            color_link_state(info.link_state),
            match info.v6ll {
                None => format!("{}", "none".bright_red()),
                Some(a) => format!("{}", a.addr.to_string().cyan()),
            },
            match &info.peer {
                None => format!("{}", "none".bright_red()),
                Some(p) => format!("{}", p.remote_addr.to_string().cyan()),
            },
            match &info.peer {
                None => format!("{}", "~".bright_red()),
                Some(p) => {
                    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(n) => {
                            let delta = n.as_millis() - p.last_seen;
                            format!("{} ms", delta)
                        }
                        Err(e) => {
                            format!("{}: {}", "failed to get system time".bright_red(), e)
                        }
                    }
                }
            },
            match &info.peer {
                None => format!("{}", "~".bright_red()),
                Some(p) => {
                    match &p.lie {
                        None => format!("{}", "~".bright_red()),
                        Some(lie) => format!("{} ({})", lie.name.bright_green(), match p.neighbor{
                            None => format!("{}", "~".bright_red()),
                            Some(nbr) => format!("{}", nbr.originator),
                        })
                    }
                }
            }
        )?;

    }
    tw.flush()?;

    //println!("{:#?}", response);

    Ok(())

}

fn lsdb(_opts: &Opts, _s: &Lsdb) -> Result<()> {

    let mut tw = TabWriter::new(stdout());
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\n",
        "System Id".dimmed(),
        "Link Id".dimmed(),
        "<~>".dimmed(),
        "System Id".dimmed(),
        "Link Id".dimmed(),
    )?;
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\n",
        "---------".bright_black(),
        "-------".bright_black(),
        "---".bright_black(),
        "---------".bright_black(),
        "-------".bright_black(),
    )?;

    let response: rift::admin::LSDBResult = 
        reqwest::blocking::get("http://localhost:7000/lsdb")?.json()?;

    for entry in response.lsdb {
        write!(
            &mut tw,
            "{} ({})\t{}\t<->\t{} ({})\t{}\n",
            match response.info.get(&entry.a.system_id) {
                None => "?",
                Some(n) => &n.name,
            },
            entry.a.system_id.to_string(),
            entry.a.link_id.to_string(),
            match response.info.get(&entry.b.system_id) {
                None => "?",
                Some(n) => &n.name,
            },
            entry.b.system_id.to_string(),
            entry.b.link_id.to_string(),
        )?;
    }
    tw.flush()?;

    Ok(())

}

fn color_rift_state(state: rift::link::State) -> String {
    match state {
        rift::link::State::WaitForCarrier => format!("{}", "wait for carrier".to_string().bright_red()),
        rift::link::State::WaitForV6ll => format!("{}", "wait for v6ll".to_string().bright_yellow()),
        rift::link::State::Solicit => format!("{}", "solicit".to_string().bright_yellow()),
        rift::link::State::OneWay => format!("{}", "one-way".to_string().bright_yellow()),
        rift::link::State::TwoWay => format!("{}", "two-way".to_string().bright_yellow()),
        rift::link::State::ThreeWay => format!("{}", "three-way".to_string().bright_green()),
    }
}

fn color_link_state(state: platform::LinkState) -> String {
    match state {
        platform::LinkState::Unknown => format!("{}", "unknown".to_string().bright_red()),
        platform::LinkState::Down => format!("{}", "down".to_string().bright_red()),
        platform::LinkState::Up => format!("{}", "up".to_string().bright_green()),
    }
}
