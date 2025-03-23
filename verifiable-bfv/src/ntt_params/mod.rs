// use this path to set the ring dimension N (i.e. for N=512 set the path to "params_512.rs")
// make sure to adjust the value of circuit_size in line 57 of "ivc_based_vpbs.rs" if
// using a value other than 8 or 1024
#[path = "params_8.rs"]
pub(crate) mod params;
