/* C implementation by Christophe Devine, C++ "class-ified" by [T3] */

#ifndef NOMD5_H
#define NOMD5_H

#include <no/noglobal.h>
#include <string>

#ifndef uint8
#define uint8 uchar
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct
{
    uint32 total[2];
    uint32 state[4];
    uint8 buffer[64];
} md5_context;

class NO_EXPORT NoMD5
{
protected:
    char m_szMD5[33];

public:
    NoMD5();
    NoMD5(const std::string& sText);
    NoMD5(const char* szText, uint32 nTextLen);
    ~NoMD5();

    operator std::string() const { return (std::string)m_szMD5; }

    operator char*() const { return (char*)m_szMD5; }

    char* MakeHash(const char* szText, uint32 nTextLen);

protected:
    void md5_starts(md5_context* ctx) const;
    void md5_update(md5_context* ctx, const uint8* input, uint32 length) const;
    void md5_finish(md5_context* ctx, uint8 digest[16]) const;

private:
    void md5_process(md5_context* ctx, const uint8 data[64]) const;
};

#endif // NOMD5_H
