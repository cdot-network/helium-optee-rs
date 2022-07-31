/*
 * Copyright (c) 2021, Qingdao IotPi Information Technology Ltd.
 * All rights reserved.
 *
 */
#ifndef TA_HELIUM_H
#define TA_HELIUM_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_HELIUM_UUID \
	{ 0x755c7d73, 0x41a1, 0x4f9a, \
		{ 0xb8, 0x29, 0x6a, 0x91, 0xb9, 0xfd, 0xf1, 0x09} }

#if 0
/*
 * in	params[0].value.a key size
 */
#define TA_HELIUM_CMD_GEN_ECDSA_KEYPAIR		2
#endif 
/*
 * in  params[0].value.a input: slot
 * in  params[1].memref input: message digest
 * out params[2].memref output: signature
 */
#define TA_HELIUM_CMD_ECDSA_SIGN            4
/*
 * in  params[0].value.a input: slot
 * in  params[1].memref input: ECC PUBLIC KEY X
 * in  params[2].memref input: ECC PUBLIC KEY Y
 * out params[3].memref output: signature
 */

#define TA_HELIUM_CMD_ECDH                  5

#if 0
/*
 * in	params[0].value.a key size
 */
#define TA_HELIUM_CMD_GEN_ECDH_KEYPAIR		6
#endif

/*
 * in  params[0].value.a input: slot
 * in  params[1].memref output: ECC PUBLIC KEY X
 * in  params[2].memref output: ECC PUBLIC KEY Y
 */
#define TA_HELIUM_CMD_GET_ECC_PUBLICKEY		7
/*
 * in  params[0].value.a input: slot
 * in  params[1].memref input: message digest
 * in  params[2].memref input: signature
 */
#define TA_HELIUM_CMD_ECDSA_VERIFY          8
/*
 * in	params[0].value.a key slot
 */
#define TA_HELIUM_CMD_GEN_ECC_KEYPAIR		9

#define TA_HELIUM_CMD_DEL_ECC_KEYPAIR		10

#endif /*TA_HELIUM_H*/
