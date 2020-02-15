app_enclave.so
{
    global:
        enclave_entry;
        g_global_data_sim;
        g_global_data;
        g_peak_heap_used;
    local:
        *;
};

# NOTE(!): if g_global_data not there, will fail signing with no useful error msg!!