use std::fmt::{self, Display};

pub struct ListingFormatter {
    indent: usize,
    values: Vec<(&'static str, String)>,
}

impl ListingFormatter {
    pub fn new(indent: usize) -> Self {
        Self {
            indent,
            values: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &'static str, value: impl Display) {
        self.values.push((name, value.to_string()));
    }
}

impl Display for ListingFormatter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max_name_width = self
            .values
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .expect("empty listing");

        for (name, value) in self.values.iter() {
            let padding = max_name_width - name.len();

            writeln!(
                f,
                "{}{name}:{} {value}",
                " ".repeat(self.indent),
                " ".repeat(padding)
            )?;
        }

        Ok(())
    }
}
