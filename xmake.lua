set_languages("c++20")
add_rules("mode.debug", "mode.release")
add_requires("xxhash", "capstone")


target("NvdecTrace")
    set_basename("inject")
    set_prefixname("")
    set_extension("")

    add_files("src/*.cpp")

    add_includedirs("classes",
        "open-gpu-kernel-modules/src/common/inc",
        "open-gpu-kernel-modules/src/common/sdk/nvidia/inc",
        "open-gpu-kernel-modules/src/common/sdk/nvidia/inc/class",
        "open-gpu-kernel-modules/src/common/sdk/nvidia/inc/ctrl",
        "open-gpu-kernel-modules/src/nvidia/generated",
        "open-gpu-kernel-modules/src/nvidia/arch/nvalloc/unix/include",
        "open-gpu-kernel-modules/kernel-open/nvidia-uvm")

    add_packages("xxhash", "capstone")

    set_kind("shared")
