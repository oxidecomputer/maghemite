use std::io;
//use termion::raw::IntoRawMode;
use std::io::Read;
use tui::backend::CrosstermBackend;
use tui::layout::Constraint;
use tui::layout::Direction;
use tui::layout::Layout;
use tui::style::Color;
use tui::style::Style;
use tui::text::Span;
use tui::widgets::Block;
use tui::widgets::Borders;
use tui::widgets::Row;
use tui::widgets::Table;
use tui::Terminal;

// TODO: this is all mock up at the moment, just seeing if tui is a reasonable
// .     way to get a simple terminal based interface into the routers

fn main() -> Result<(), io::Error> {
    //let stdout = io::stdout().into_raw_mode()?;
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    terminal.draw(|f| {
        let size = f.size();

        let title =
            Span::styled("[L1]", Style::default().fg(Color::Rgb(207, 94, 122)));

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(73, 105, 246)));
        f.render_widget(block, size);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints(
                [
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                ]
                .as_ref(),
            )
            .split(size);

        let peer_table = peer_table();
        f.render_widget(peer_table, chunks[0]);

        let direct_table = direct_table();
        f.render_widget(direct_table, chunks[1]);

        let indirect_table = indirect_table();
        f.render_widget(indirect_table, chunks[2]);
    })?;

    loop {
        let input: Option<i32> = io::stdin()
            .bytes()
            .next()
            .and_then(|result| result.ok())
            .map(|byte| byte as i32);

        if let Some(0x3) = input {
            break;
        }
    }

    Ok(())
}

fn peer_table<'a>() -> Table<'a> {
    let title =
        Span::styled("[Peers]", Style::default().fg(Color::Rgb(245, 206, 99)));
    Table::new(vec![
        Row::new(vec!["H1", "fe80::7:1"]),
        Row::new(vec!["H2", "fe80::8:1"]),
    ])
    .block(Block::default().title(title))
    .header(
        Row::new(vec!["peer", "address"])
            .style(Style::default().fg(Color::DarkGray)),
    )
    .widths(&[Constraint::Percentage(50), Constraint::Percentage(50)])
}

fn direct_table<'a>() -> Table<'a> {
    let title =
        Span::styled("[Direct]", Style::default().fg(Color::Rgb(245, 206, 99)));

    Table::new(vec![
        Row::new(vec!["fd00:1701:d:0101::/64", "fe80::7:1"]),
        Row::new(vec!["fd00:1701:d:0102::/64", "fe80::8:1"]),
    ])
    .block(Block::default().title(title))
    .header(
        Row::new(vec!["prefix", "nexthop"])
            .style(Style::default().fg(Color::DarkGray)),
    )
    .widths(&[Constraint::Percentage(50), Constraint::Percentage(50)])
}

fn indirect_table<'a>() -> Table<'a> {
    let title = Span::styled(
        "[Inirect]",
        Style::default().fg(Color::Rgb(245, 206, 99)),
    );

    Table::new(vec![
        Row::new(vec!["fd00:1701:d:02::/56", "R2.L1"]),
        Row::new(vec!["fd00:1701:d:02::/56", "R2.L2"]),
    ])
    .block(Block::default().title(title))
    .header(
        Row::new(vec!["prefix", "router"])
            .style(Style::default().fg(Color::DarkGray)),
    )
    .widths(&[Constraint::Percentage(50), Constraint::Percentage(50)])
}
