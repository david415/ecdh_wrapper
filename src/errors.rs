// errors.rs - ecdh errors
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::error::{Error};
use std::fmt;

#[derive(Debug)]
pub enum KeyError {
    InvalidSize,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::KeyError::*;
        match self {
            InvalidSize => write!(f, "Invalid authentication message size."),
        }
    }
}


impl Error for KeyError {
    fn description(&self) -> &str {
        "I'm a command error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::KeyError::*;
        match self {
            InvalidSize => None,
        }
    }
}
