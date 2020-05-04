project(setup_microbench
        LANGUAGES C)

add_executable(seng_mbench prog_setup.c)
add_executable(pure_mbench prog_pure_setup.c)
