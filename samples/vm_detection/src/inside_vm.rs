use std::arch::x86_64::{CpuidResult, __cpuid, _rdtsc};

/// Compute cpuid cpu cycles average.
///
/// Perform `low + samples + high` measurements,
/// discard `low` and `high` (outliers),
/// compute average using the remaining `samples` measurements.
///
/// Prefer `inside_vm::inside_vm()` or `inside_vm::inside_vm_custom()`.
///
/// This function uses `unsafe`.
///
/// ```
/// use inside_vm::cpuid_cycle_count_avg;
/// // perform 5 + 100 + 10 = 115 measurements
/// // discard 5 lowest and 10 highest measurements
/// // compute average over the 100 remaining measurements
/// let avg = cpuid_cycle_count_avg(5, 100, 10);
/// ```
pub fn cpuid_cycle_count_avg(low: usize, samples: usize, high: usize) -> u64 {
    let mut tsc1: u64;
    let mut tsc2: u64;
    let mut cycles: Vec<u64> = vec![];
    let mut cpuid = CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    for _ in 0..(low + samples + high) {
        unsafe {
            tsc1 = _rdtsc();
            cpuid = __cpuid(0);
            tsc2 = _rdtsc();
        }
        cycles.push(tsc2 - tsc1);
    }
    unsafe {
        // call to __cpuid would be optimized away by the compiler in release mode
        // if it were not for this call
        std::ptr::read_volatile(&cpuid);
    }

    // remove low and high outliers, keep samples
    cycles.sort_unstable();
    let cycles_without_outliers = &cycles[low..low + samples];

    // compute average cycle count without outliers, make sure we do not divide by zero
    let avg = cycles_without_outliers.iter().sum::<u64>() / std::cmp::max(samples as u64, 1);
    avg
}

/// Detect if inside vm by computing cpuid cpu cycles average and compare to `threshold`.
///
/// Perform `low + samples + high` measurements,
/// discard `low` and `high` (outliers),
/// compute average using the remaining `samples` measurements.
///
/// Compare average to `threshold`, if above return true else false.
///
/// Example
/// ```
/// use inside_vm::inside_vm_custom;
/// let inside: bool = inside_vm::inside_vm_custom(5, 100, 5, 1_000);
/// ```
pub fn inside_vm_custom(low: usize, samples: usize, high: usize, threshold: u64) -> bool {
    cpuid_cycle_count_avg(low, samples, high) > threshold
}

/// Compute cpuid cpu cycles average and compare to threshold.
///
/// Same as `inside_vm_custom(5, 100, 5, 1_000)`
///
/// Example:
/// ```
/// use inside_vm::inside_vm;
/// let inside: bool = inside_vm::inside_vm();
/// ```
pub fn inside_vm() -> bool {
    inside_vm_custom(5, 100, 5, 1_000)
}
