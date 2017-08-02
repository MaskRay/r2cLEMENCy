#include <stdint.h>
typedef enum _mnemonic_t {
CLCY_SF, CLCY_MDFM, CLCY_SB, CLCY_SA, CLCY_SL, CLCY_XRI, CLCY_CMFM, CLCY_SR,
CLCY_ITF, CLCY_CR, CLCY_ADFM, CLCY_BRR, CLCY_CM, CLCY_BRA, CLCY_SAI, CLCY_RRI,
CLCY_DVIM, CLCY_FTIM, CLCY_MUF, CLCY_RNDM, CLCY_XRM, CLCY_SRIM, CLCY_DVIS, CLCY_SBCM,
CLCY_MUM, CLCY_SBCI, CLCY_MUI, CLCY_MUSM, CLCY_DVFM, CLCY_ANM, CLCY_ANI, CLCY_BF,
CLCY_BR, CLCY_MUIM, CLCY_SBC, CLCY_ADF, CLCY_ADC, CLCY_SBF, CLCY_SBI, CLCY_MS,
CLCY_ADI, CLCY_MU, CLCY_MH, CLCY_ML, CLCY_MD, CLCY_MUIS, CLCY_ADCIM, CLCY_SRI,
CLCY_EI, CLCY_SRM, CLCY_ITFM, CLCY_ORM, CLCY_ADIM, CLCY_MDS, CLCY_MDIM, CLCY_MDI,
CLCY_DBRK, CLCY_LDS, CLCY_LDT, CLCY_LDW, CLCY_ORI, CLCY_DVISM, CLCY_MDF, CLCY_RRIM,
CLCY_DV, CLCY_SBCIM, CLCY_MDIS, CLCY_BFM, CLCY_MDM, CLCY_DI, CLCY_MUISM, CLCY_MDSM,
CLCY_MDISM, CLCY_CAA, CLCY_RLIM, CLCY_WT, CLCY_STW, CLCY_NGF, CLCY_SLM, CLCY_STT,
CLCY_STS, CLCY_SLI, CLCY_SBFM, CLCY_NGM, CLCY_OR, CLCY_ADM, CLCY_XR, CLCY_SAM,
CLCY_B, CLCY_C, CLCY_SBM, CLCY_MUFM, CLCY_SLIM, CLCY_SEW, CLCY_SES, CLCY_RND,
CLCY_SAIM, CLCY_NG, CLCY_DVM, CLCY_DVI, CLCY_DVF, CLCY_ADCI, CLCY_ADCM, CLCY_CAR,
CLCY_NT, CLCY_CMIM, CLCY_DMT, CLCY_SMP, CLCY_DVS, CLCY_RMP, CLCY_IR, CLCY_RRM,
CLCY_FTI, CLCY_MUS, CLCY_AN, CLCY_NTM, CLCY_AD, CLCY_RR, CLCY_RL, CLCY_RE,
CLCY_RF, CLCY_HT, CLCY_SBIM, CLCY_RLM, CLCY_RLI, CLCY_DVSM, CLCY_CMM, CLCY_ZES,
CLCY_CMI, CLCY_ZEW, CLCY_CMF, CLCY_NGFM,
} mnemonic_t;
typedef struct _decode_result_t {
mnemonic_t mnemonic;

uint64_t Memory_Offset; uint64_t Register_Count; uint64_t Adjust_rB; uint64_t Memory_Flags; uint64_t rA; uint64_t rB; uint64_t rC; uint64_t UF;
uint64_t Offset_unsigned; int64_t Offset_signed; uint64_t Immediate_unsigned; int64_t Immediate_signed; uint64_t Condition; uint64_t Location;
} decode_result_t;
int _decode(uint64_t inst, decode_result_t * retv, int small);

int decode(uint64_t inst, decode_result_t * retv)
{
    int r = 0;
    r = _decode((inst >> (64-9) << (64 - 18)) | (inst << 9 >> (64 - 9) << (64 - 9)) | (inst & 0x3fffffffffff), retv, 1);
    if (r != 0) return r;
    r = _decode((inst >> (64-9) << (64 - 18)) | (inst << 9 >> (64 - 9) << (64 - 9)) | (inst << 27 >> (64 - 9) << (64 - 36 - 9)) | (inst << 36 >> (64 - 9) << (64 - 27 - 9)) | (inst & 0x3fe00007ffff), retv, 0);
    if (r != 0) return r;
    return 0;
}

int _decode(uint64_t inst, decode_result_t * retv, int small)
{
	return 0;
}

int decode_byte(const ut8 * bytes, int bit_offset, decode_result_t * retv)
{
    uint64_t inst = 0;
    for (int i = 0; i < 8; i++)
    {
        if (i == 0)
           inst |= ((uint64_t)((uint8_t)bytes[i]<<bit_offset)<<(64-8));
        else
            inst |= (((uint64_t)(uint8_t)bytes[i]) << (bit_offset + 64 - i * 8 - 8));
    }
    return decode(inst, retv);
}
