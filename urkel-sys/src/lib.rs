#[allow(non_camel_case_types)]
mod bindings;
pub use bindings::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
