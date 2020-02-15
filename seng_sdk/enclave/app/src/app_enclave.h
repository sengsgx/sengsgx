#ifndef SENG_T_RUNTIME_H
#define SENG_T_RUNTIME_H

#if defined(__cplusplus)
extern "C" {
#endif

extern void printf(const char *fmt, ...);

#define TEST_CHECK(status)  \
    {   \
            if (status != SGX_SUCCESS) {    \
                        printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);  \
                        abort();    \
                    }   \
    }

#if defined(__cplusplus)
}
#endif

#endif /* !SENG_U_RUNTIME_H */
