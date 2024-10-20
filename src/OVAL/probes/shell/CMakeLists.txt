if(OPENSCAP_PROBE_SHELL_CMD)
    list(APPEND SHELL_PROBES_SOURCES
        "cmd_probe.c"
        "cmd_probe.h"
    )
endif()

add_library(shell_probes_object OBJECT ${SHELL_PROBES_SOURCES})
set_oscap_generic_properties(shell_probes_object)