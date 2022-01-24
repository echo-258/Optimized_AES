// 2019302180042 张家赫
# include <stdint.h>
# include <stdio.h>
# include <string.h>
# include <time.h>
# include <stdlib.h>
# include "tables.h"

typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
}AesKey;

#define BLOCKSIZE 16  //AES-128分组长度为16字节

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// 从uint32_t x中提取从低位开始的第n个字节
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// 字节替换然后循环左移1位
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
// AES-128轮常量
static const uint32_t rcon[10] = {
        0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
        0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL
};
// S盒
unsigned char S[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

//逆S盒
unsigned char inv_S[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

//加密秘钥扩展
int keyExpansion_en(const uint8_t *key, uint32_t keyLen, AesKey *aesKey) {
    uint32_t *w = aesKey->eK;  //加密秘钥
    /* keyLen is 16 Bytes, generate uint32_t W[44]. */
    /* W[0-3] */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + (i << 2));
    }
    /* W[4-43] */
    for (int i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }
    return 0;
}

// 解密密钥扩展
int keyExpansion_de(const uint8_t *key, uint32_t keyLen, AesKey *aesKey) {
    uint32_t *w = aesKey->eK;  //加密秘钥
    uint32_t *v = aesKey->dK;  //解密秘钥
    uint8_t mat[4][4] = {0};
    uint32_t dk_col[4] = {0};
    /* keyLen is 16 Bytes, generate uint32_t W[44]. */
    /* W[0-3] */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + (i << 2));
    }
    /* W[4-43] */
    for (int i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }

    w = aesKey->eK;
    memcpy(v, w + 40, 16);
    memcpy(v + 40, w, 16);     // 第一个和最后一个密钥不变，仅顺序颠倒
    for (int i = 4; i < 40; i += 4) {
        mat[0][0] = *(w + 40 - i) >> 24; mat[0][1] = *(w + 40 - i + 1) >> 24; mat[0][2] = *(w + 40 - i + 2) >> 24; mat[0][3] = *(w + 40 - i + 3) >> 24;
        mat[1][0] = *(w + 40 - i) >> 16; mat[1][1] = *(w + 40 - i + 1) >> 16; mat[1][2] = *(w + 40 - i + 2) >> 16; mat[1][3] = *(w + 40 - i + 3) >> 16;
        mat[2][0] = *(w + 40 - i) >> 8;  mat[2][1] = *(w + 40 - i + 1) >> 8;  mat[2][2] = *(w + 40 - i + 2) >> 8;  mat[2][3] = *(w + 40 - i + 3) >> 8;
        mat[3][0] = *(w + 40 - i);       mat[3][1] = *(w + 40 - i + 1);       mat[3][2] = *(w + 40 - i + 2);       mat[3][3] = *(w + 40 - i + 3);
        *(v + i) = T_k0[mat[0][0]] ^ T_k1[mat[1][0]] ^ T_k2[mat[2][0]] ^ T_k3[mat[3][0]];
        *(v + i + 1) = T_k0[mat[0][1]] ^ T_k1[mat[1][1]] ^ T_k2[mat[2][1]] ^ T_k3[mat[3][1]];
        *(v + i + 2) = T_k0[mat[0][2]] ^ T_k1[mat[1][2]] ^ T_k2[mat[2][2]] ^ T_k3[mat[3][2]];
        *(v + i + 3) = T_k0[mat[0][3]] ^ T_k1[mat[1][3]] ^ T_k2[mat[2][3]] ^ T_k3[mat[3][3]];
    }
    return 0;
}

// AES-128加密接口，输入key应为16字节长度，输入长度应该是16字节整倍数，
// 这样输出长度与输入长度相同，函数调用外部为输出数据分配内存
int aesEncrypt(AesKey *aesKey, const uint8_t *pt, uint8_t *ct, uint32_t len) {
    uint8_t *pos = ct;
    const uint32_t *rk = aesKey->eK;  //解密秘钥指针
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    uint32_t e[4] = {0, 0, 0, 0};

    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }
    for (int i = 0; i < len; i += BLOCKSIZE) {
        // 原则：不考虑代码量的繁复，虽然语句多，但每一句的执行都很直接
        // 代码数量多 未必执行慢 在一个分组中 唯一的循环是加密轮次 要做的事情一目了然
        // 初始轮密钥加
        e[0] = (*(pt) << 24) | (*(pt + 1) << 16) | (*(pt + 2) << 8) | *(pt + 3);
        e[0] ^= *(rk);
        e[1] = (*(pt + 4) << 24) | (*(pt + 5) << 16) | (*(pt + 6) << 8) | *(pt + 7);
        e[1] ^= *(rk + 1);
        e[2] = (*(pt + 8) << 24) | (*(pt + 9) << 16) | (*(pt + 10) << 8) | *(pt + 11);
        e[2] ^= *(rk + 2);
        e[3] = (*(pt + 12) << 24) | (*(pt + 13) << 16) | (*(pt + 14) << 8) | *(pt + 15);
        e[3] ^= *(rk + 3);
        // 转为矩阵
        state[0][0] = e[0] >> 24;       state[0][1] = e[1] >> 24;       state[0][2] = e[2] >> 24;       state[0][3] = e[3] >> 24;
        state[1][0] = e[0] >> 16;       state[1][1] = e[1] >> 16;       state[1][2] = e[2] >> 16;       state[1][3] = e[3] >> 16;
        state[2][0] = e[0] >> 8;        state[2][1] = e[1] >> 8;        state[2][2] = e[2] >> 8;        state[2][3] = e[3] >> 8;
        state[3][0] = e[0];             state[3][1] = e[1];             state[3][2] = e[2];             state[3][3] = e[3];

        // 下面的实现方法也可以。在本设备上未能成功比较得到较优方案
        // state[0][0] = *(pt) ^ (*(rk) >> 24);            state[0][1] = *(pt + 4) ^ (*(rk + 1) >> 24);
        // state[0][2] = *(pt + 8) ^ (*(rk + 2) >> 24);    state[0][3] = *(pt + 12) ^ (*(rk + 3) >> 24);
        // state[1][0] = *(pt + 1) ^ (*(rk) >> 16);        state[1][1] = *(pt + 5) ^ (*(rk + 1) >> 16);
        // state[1][2] = *(pt + 9) ^ (*(rk + 2) >> 16);    state[1][3] = *(pt + 13) ^ (*(rk + 3) >> 16);
        // state[2][0] = *(pt + 2) ^ (*(rk) >> 8);         state[2][1] = *(pt + 6) ^ (*(rk + 1) >> 8);
        // state[2][2] = *(pt + 10) ^ (*(rk + 2) >> 8);    state[2][3] = *(pt + 14) ^ (*(rk + 3) >> 8);
        // state[3][0] = *(pt + 3) ^ (*(rk));              state[3][1] = *(pt + 7) ^ (*(rk + 1));
        // state[3][2] = *(pt + 11) ^ (*(rk + 2));         state[3][3] = *(pt + 15) ^ (*(rk + 3));

        for (int j = 1; j < 10; j++) {
            rk += 4;
            e[0] = T0[state[0][0]] ^ T1[state[1][1]] ^ T2[state[2][2]] ^ T3[state[3][3]] ^ *(rk);
            e[1] = T0[state[0][1]] ^ T1[state[1][2]] ^ T2[state[2][3]] ^ T3[state[3][0]] ^ *(rk + 1);
            e[2] = T0[state[0][2]] ^ T1[state[1][3]] ^ T2[state[2][0]] ^ T3[state[3][1]] ^ *(rk + 2);
            e[3] = T0[state[0][3]] ^ T1[state[1][0]] ^ T2[state[2][1]] ^ T3[state[3][2]] ^ *(rk + 3);

            // 一轮计算结束 更新状态
            state[0][0] = e[0] >> 24;       state[0][1] = e[1] >> 24;       state[0][2] = e[2] >> 24;       state[0][3] = e[3] >> 24;
            state[1][0] = e[0] >> 16;       state[1][1] = e[1] >> 16;       state[1][2] = e[2] >> 16;       state[1][3] = e[3] >> 16;
            state[2][0] = e[0] >> 8;        state[2][1] = e[1] >> 8;        state[2][2] = e[2] >> 8;        state[2][3] = e[3] >> 8;
            state[3][0] = e[0];             state[3][1] = e[1];             state[3][2] = e[2];             state[3][3] = e[3];
        }

        rk += 4;

        pos[0] = (*(rk) >> 24) ^ S[state[0][0]];    pos[1] = (*(rk) >> 16) ^ S[state[1][1]];
        pos[2] = (*(rk) >> 8) ^ S[state[2][2]];    pos[3] = (*(rk)) ^ S[state[3][3]];
        pos[4] = (*(rk + 1) >> 24) ^ S[state[0][1]];    pos[5] = (*(rk + 1) >> 16) ^ S[state[1][2]];
        pos[6] = (*(rk + 1) >> 8) ^ S[state[2][3]];    pos[7] = (*(rk + 1)) ^ S[state[3][0]];
        pos[8] = (*(rk + 2) >> 24) ^ S[state[0][2]];    pos[9] = (*(rk + 2) >> 16) ^ S[state[1][3]];
        pos[10] = (*(rk + 2) >> 8) ^ S[state[2][0]];    pos[11] = (*(rk + 2)) ^ S[state[3][1]];
        pos[12] = (*(rk + 3) >> 24) ^ S[state[0][3]];    pos[13] = (*(rk + 3) >> 16) ^ S[state[1][0]];
        pos[14] = (*(rk + 3) >> 8) ^ S[state[2][1]];    pos[15] = (*(rk + 3)) ^ S[state[3][2]];

        // 下面的实现方法也可以。在本设备上未能成功比较得到较优方案
        // e[0] = (S[state[0][0]] << 24) | (S[state[1][1]] << 16) | (S[state[2][2]] << 8) | (S[state[3][3]]);
        // e[0] ^= *(rk);
        // e[1] = (S[state[0][1]] << 24) | (S[state[1][2]] << 16) | (S[state[2][3]] << 8) | (S[state[3][0]]);
        // e[1] ^= *(rk + 1);
        // e[2] = (S[state[0][2]] << 24) | (S[state[1][3]] << 16) | (S[state[2][0]] << 8) | (S[state[3][1]]);
        // e[2] ^= *(rk + 2);
        // e[3] = (S[state[0][3]] << 24) | (S[state[1][0]] << 16) | (S[state[2][1]] << 8) | (S[state[3][2]]);
        // e[3] ^= *(rk + 3);
        // // 写入结果
        // pos[0] = e[0] >> 24;        pos[1] = e[0] >> 16;        pos[2] = e[0] >> 8;        pos[3] = e[0];
        // pos[4] = e[1] >> 24;        pos[5] = e[1] >> 16;        pos[6] = e[1] >> 8;        pos[7] = e[1];
        // pos[8] = e[2] >> 24;        pos[9] = e[2] >> 16;        pos[10] = e[2] >> 8;        pos[11] = e[2];
        // pos[12] = e[3] >> 24;        pos[13] = e[3] >> 16;        pos[14] = e[3] >> 8;        pos[15] = e[3];

        pos += BLOCKSIZE;  // 加密数据内存指针移动到下一个分组
        pt += BLOCKSIZE;   // 明文数据指针移动到下一个分组
        rk = aesKey->eK;    // 恢复rk指针到秘钥初始位置
    }
    return 0;
}

// AES128解密， 参数要求同加密
int aesDecrypt(AesKey *aesKey, const uint8_t *ct, uint8_t *pt, uint32_t len) {
    uint8_t *pos = pt;
    const uint32_t *rk = aesKey->dK;  //解密秘钥指针
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};
    uint32_t e[4] = {0, 0, 0, 0};

    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }
    for (int i = 0; i < len; i += BLOCKSIZE) {
        // 原则：不考虑代码量的繁复，虽然语句多，但每一句的执行都很直接
        // 代码数量多 未必执行慢 在一个分组中 唯一的循环是加密轮次 要做的事情一目了然
        // 初始轮密钥加
        e[0] = (*(ct) << 24) | (*(ct + 1) << 16) | (*(ct + 2) << 8) | *(ct + 3);
        e[0] ^= *(rk);
        e[1] = (*(ct + 4) << 24) | (*(ct + 5) << 16) | (*(ct + 6) << 8) | *(ct + 7);
        e[1] ^= *(rk + 1);
        e[2] = (*(ct + 8) << 24) | (*(ct + 9) << 16) | (*(ct + 10) << 8) | *(ct + 11);
        e[2] ^= *(rk + 2);
        e[3] = (*(ct + 12) << 24) | (*(ct + 13) << 16) | (*(ct + 14) << 8) | *(ct + 15);
        e[3] ^= *(rk + 3);

        // 转为矩阵
        state[0][0] = e[0] >> 24;       state[0][1] = e[1] >> 24;       state[0][2] = e[2] >> 24;       state[0][3] = e[3] >> 24;
        state[1][0] = e[0] >> 16;       state[1][1] = e[1] >> 16;       state[1][2] = e[2] >> 16;       state[1][3] = e[3] >> 16;
        state[2][0] = e[0] >> 8;        state[2][1] = e[1] >> 8;        state[2][2] = e[2] >> 8;        state[2][3] = e[3] >> 8;
        state[3][0] = e[0];             state[3][1] = e[1];             state[3][2] = e[2];             state[3][3] = e[3];

        for (int j = 1; j < 10; j++) {
            rk += 4;
            // 这部分与加密是不一样的！
            e[0] = T_inv0[state[0][0]] ^ T_inv1[state[1][3]] ^ T_inv2[state[2][2]] ^ T_inv3[state[3][1]] ^ *(rk);
            e[1] = T_inv0[state[0][1]] ^ T_inv1[state[1][0]] ^ T_inv2[state[2][3]] ^ T_inv3[state[3][2]] ^ *(rk + 1);
            e[2] = T_inv0[state[0][2]] ^ T_inv1[state[1][1]] ^ T_inv2[state[2][0]] ^ T_inv3[state[3][3]] ^ *(rk + 2);
            e[3] = T_inv0[state[0][3]] ^ T_inv1[state[1][2]] ^ T_inv2[state[2][1]] ^ T_inv3[state[3][0]] ^ *(rk + 3);

            // 一轮计算结束 更新状态
            state[0][0] = e[0] >> 24;       state[0][1] = e[1] >> 24;       state[0][2] = e[2] >> 24;       state[0][3] = e[3] >> 24;
            state[1][0] = e[0] >> 16;       state[1][1] = e[1] >> 16;       state[1][2] = e[2] >> 16;       state[1][3] = e[3] >> 16;
            state[2][0] = e[0] >> 8;        state[2][1] = e[1] >> 8;        state[2][2] = e[2] >> 8;        state[2][3] = e[3] >> 8;
            state[3][0] = e[0];             state[3][1] = e[1];             state[3][2] = e[2];             state[3][3] = e[3];
        }

        rk += 4;
        
        // e[0] = (inv_S[state[0][0]] << 24) | (inv_S[state[1][3]] << 16) | (inv_S[state[2][2]] << 8) | (inv_S[state[3][1]]);
        // e[0] ^= *(rk);
        // e[1] = (inv_S[state[0][1]] << 24) | (inv_S[state[1][0]] << 16) | (inv_S[state[2][3]] << 8) | (inv_S[state[3][2]]);
        // e[1] ^= *(rk + 1);
        // e[2] = (inv_S[state[0][2]] << 24) | (inv_S[state[1][1]] << 16) | (inv_S[state[2][0]] << 8) | (inv_S[state[3][3]]);
        // e[2] ^= *(rk + 2);
        // e[3] = (inv_S[state[0][3]] << 24) | (inv_S[state[1][2]] << 16) | (inv_S[state[2][1]] << 8) | (inv_S[state[3][0]]);
        // e[3] ^= *(rk + 3);
        // // 写入结果
        // pos[0] = e[0] >> 24;        pos[1] = e[0] >> 16;        pos[2] = e[0] >> 8;        pos[3] = e[0];
        // pos[4] = e[1] >> 24;        pos[5] = e[1] >> 16;        pos[6] = e[1] >> 8;        pos[7] = e[1];
        // pos[8] = e[2] >> 24;        pos[9] = e[2] >> 16;        pos[10] = e[2] >> 8;        pos[11] = e[2];
        // pos[12] = e[3] >> 24;        pos[13] = e[3] >> 16;        pos[14] = e[3] >> 8;        pos[15] = e[3];

        pos[0] = (*(rk) >> 24) ^ inv_S[state[0][0]];    pos[1] = (*(rk) >> 16) ^ inv_S[state[1][3]];
        pos[2] = (*(rk) >> 8) ^ inv_S[state[2][2]];    pos[3] = (*(rk)) ^ inv_S[state[3][1]];
        pos[4] = (*(rk + 1) >> 24) ^ inv_S[state[0][1]];    pos[5] = (*(rk + 1) >> 16) ^ inv_S[state[1][0]];
        pos[6] = (*(rk + 1) >> 8) ^ inv_S[state[2][3]];    pos[7] = (*(rk + 1)) ^ inv_S[state[3][2]];
        pos[8] = (*(rk + 2) >> 24) ^ inv_S[state[0][2]];    pos[9] = (*(rk + 2) >> 16) ^ inv_S[state[1][1]];
        pos[10] = (*(rk + 2) >> 8) ^ inv_S[state[2][0]];    pos[11] = (*(rk + 2)) ^ inv_S[state[3][3]];
        pos[12] = (*(rk + 3) >> 24) ^ inv_S[state[0][3]];    pos[13] = (*(rk + 3) >> 16) ^ inv_S[state[1][2]];
        pos[14] = (*(rk + 3) >> 8) ^ inv_S[state[2][1]];    pos[15] = (*(rk + 3)) ^ inv_S[state[3][0]];

        pos += BLOCKSIZE;  // 加密数据内存指针移动到下一个分组
        ct += BLOCKSIZE;   // 明文数据指针移动到下一个分组
        rk = aesKey->dK;    // 恢复rk指针到秘钥初始位置
    }
    return 0;
}

void printHex(uint8_t *ptr, int len, char *tag) {
    printf("%s\ndata[%d]: ", tag, len);
    for (int i = 0; i < len; ++i) {
        printf("%.2X ", *ptr++);
    }
    printf("\n");
}

int main() {
    uint8_t pt[16] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf, 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};
    uint8_t key[16] = {0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94};
    uint8_t ct[16] = {0};     // 加密后的数据
    uint8_t plain[16] = {0};  // 解密后的数据
    clock_t start, end;
    uint8_t *plain_text, *encrypt_text, *decrypt_text;
    uint8_t part[1000]={0};
    uint32_t filesize;

    AesKey aesKey;
    keyExpansion_de(key, 16, &aesKey);      // 密钥扩展

    char fname[32] = {0};

    // printf("input file name:\n");
    // scanf("%s", fname);
    strcpy(fname, "TestText.txt");
    printf("file : %s\n", fname);
    FILE *fp = fopen(fname, "rb");
    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    plain_text = (uint8_t *)malloc(filesize);
    encrypt_text = (uint8_t *)malloc(filesize);
    decrypt_text = (uint8_t *)malloc(filesize);
    plain_text[0] = 0;
    encrypt_text[0] = 0;
    decrypt_text[0] = 0;
    rewind(fp);
    printf("Reading File...\n");
    while((fgets(part,1024,fp))!=NULL){//循环读取1024字节,如果没有数据则退出循环
        strcat(plain_text, part);//拼接字符串
    }
    fclose(fp);
    // puts(plain_text);
    printf("Read file over.\n");

    start = clock();
    aesEncrypt(&aesKey, plain_text, encrypt_text, filesize);
    end = clock();
    printf("\nEncrypt time=%fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    start = clock();
    aesDecrypt(&aesKey, encrypt_text, decrypt_text, filesize);
    end = clock();
    printf("\nDecrypt time=%fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    // printf("===after decryption===\n");
    // puts(decrypt_text);

    printf("\nWriting file...\n");
    FILE *fp1 = fopen("decpypt.txt", "w");
    fputs(decrypt_text, fp);
    fclose(fp);
    printf("Write file over.\n");
    free(plain_text);
    free(encrypt_text);
    free(decrypt_text);

    // printHex(pt, 16, "plain data:");    // 打印初始明文数据
    // start = clock();
    // // 1GB = 1024 * 1024 * 1024 = 67108864 * 16
    // // 1MB = 1024 * 1024 = 65536
    // // 10MB = 1024 * 1024 * 10 = 655360 * 16
    // for (int i = 0; i < 655360; i++) {
    //     aesEncrypt(&aesKey, pt, ct, 16);     // 加密
    // }
    // end = clock();
    // printf("\nEncrypt time=%fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    // printHex(ct, 16, "after encryption:");  // 打印加密后的密文

    // start = clock();
    // for (int i = 0; i < 655360; i++) {
    //     aesDecrypt(&aesKey, ct, plain, 16);    // 解密
    // }
    // end = clock();
    // printf("\nDecrypt time=%fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    // printHex(plain, 16, "after decryption:"); // 打印解密后的明文数据

    return 0;
}

