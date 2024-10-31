set_languages("c++20")
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

    add_packages("libxxhash", "capstone")

    set_kind("shared")
