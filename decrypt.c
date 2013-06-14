#include "preprocess.h"
#include "wireless-defender.h"
#include "analyse.h"
#include "decrypt.h"

const short TkipSbox[2][256]=
{
    {
        0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
        0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
        0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
        0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
        0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
        0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
        0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
        0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
        0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
        0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
        0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
        0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
        0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
        0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
        0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
        0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
        0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
        0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
        0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
        0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
        0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
        0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
        0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
        0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
        0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
        0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
        0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
        0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
        0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
        0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
        0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
        0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A
    },
    {
        0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
        0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
        0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
        0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
        0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
        0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
        0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
        0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
        0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
        0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
        0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
        0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
        0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
        0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
        0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
        0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
        0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
        0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
        0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
        0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
        0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
        0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
        0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
        0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
        0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
        0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
        0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
        0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
        0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
        0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
        0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
        0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C
    }
};

void 
merge_iv( u_char *bytes, int frame_len,	u_char key[40] )
{
	int i, j = 3;

	memcpy( key, bytes, 3 );
	for( i = 0; i < user->passwd_len; i += 2 ) {
		key[j++] = user->passwd[i]*16 + user->passwd[i+1];	
	}
}

void
wep_decrypt( u_char *data, u_char *key, int len, int keylen )
{
	RC4_KEY rc4_key;

	RC4_set_key( &rc4_key, keylen, key );
	RC4( &rc4_key, len, data, data );
}

void 
calc_pmk( char *key, char *essid_pre, u_char pmk[40] ) 
{
	int i, j, slen;
	u_char buffer[65];
	char essid[33+4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	memset( essid, 0, sizeof( essid ) );
	memcpy( essid, essid_pre, strlen( essid_pre ) );
	slen = strlen( essid ) + 4;

	/* setup the inner and outer contexts */

	memset( buffer, 0, sizeof( buffer ) );
	strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

	for( i = 0; i < 64; i++ ) {
		buffer[i] ^= 0x36;
	}

	SHA1_Init( &ctx_ipad );
	SHA1_Update( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ ) {
		buffer[i] ^= 0x6A;
	}

	SHA1_Init( &ctx_opad );
	SHA1_Update( &ctx_opad, buffer, 64 );

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC( EVP_sha1(), ( u_char * )key, strlen( key ), 
				( u_char* )essid, slen, pmk, NULL );
	memcpy( buffer, pmk, 20 );

	for( i = 1; i < 4096; i++ ) {
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ ) {
			pmk[j] ^= buffer[j];
		}
	}

	essid[slen - 1] = '\2';
	HMAC( EVP_sha1(), ( u_char * )key, strlen( key ), 
					( u_char* )essid, slen, pmk+20, NULL );
	memcpy( buffer, pmk + 20, 20 );

	for( i = 1; i < 4096; i++ ) {
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ ) {
			pmk[j + 20] ^= buffer[j];
		}
	}
}

int
calc_ptk( u_char pmk[40] )
{
	int i;
	u_char pke[100];
	u_char mic[20];
	char ssid[40] = {0};
	char *passwd = "wufeishizhu.";

	memcpy( ssid, AP_list->cur->ssid, strlen( AP_list->cur->ssid ) );
	ssid[strlen(ssid)] = '\0';

	calc_pmk( passwd, ssid, pmk );

    memcpy( pke, "Pairwise key expansion", 23 );

    if( memcmp( wpa->stmac, wpa->bssid, 6 ) < 0 ) {
        memcpy( pke + 23, wpa->stmac, 6 );
        memcpy( pke + 29, wpa->bssid, 6 );
    } else {
        memcpy( pke + 23, wpa->bssid, 6 );
        memcpy( pke + 29, wpa->stmac, 6 );
    }

    if( memcmp( wpa->snonce, wpa->anonce, 32 ) < 0 ) {
        memcpy( pke + 35, wpa->snonce, 32 );
        memcpy( pke + 67, wpa->anonce, 32 );
    } else {
        memcpy( pke + 35, wpa->anonce, 32 );
        memcpy( pke + 67, wpa->snonce, 32 );
    }

    for( i = 0; i < 4; i++ )
    {
        pke[99] = i;
        HMAC(EVP_sha1(), pmk, 32, pke, 100, wpa->ptk + i * 20, NULL );
    }

    if( ( wpa->keyver & 0x07 ) == 1 )
        HMAC(EVP_md5(), wpa->ptk, 16, wpa->eapol, 
										wpa->eapol_size, mic, NULL );
    else
        HMAC(EVP_sha1(), wpa->ptk, 16, wpa->eapol, 
										wpa->eapol_size, mic, NULL );

    return( memcmp( mic, wpa->keymic, 16 ) == 0 );
}

int 
calc_tkip_ppk( u_char *bytes, int caplen, u_char TK1[16], u_char key[16] )
{
    int i;
    uint32_t IV32;
    uint16_t IV16;
    uint16_t PPK[6];

    IV16 = MK16( bytes[0], bytes[2] );

    IV32 = ( bytes[4]       ) | ( bytes[5] <<  8 ) |
           ( bytes[6] << 16 ) | ( bytes[7] << 24 );

    PPK[0] = LO16( IV32 );
    PPK[1] = HI16( IV32 );
    PPK[2] = MK16( wpa->stmac[1], wpa->stmac[0] );
    PPK[3] = MK16( wpa->stmac[3], wpa->stmac[2] );
    PPK[4] = MK16( wpa->stmac[5], wpa->stmac[4] );

    for( i = 0; i < 8; i++ )
    {
        PPK[0] += _S_( PPK[4] ^ TK16( (i & 1) + 0 ) );
        PPK[1] += _S_( PPK[0] ^ TK16( (i & 1) + 2 ) );
        PPK[2] += _S_( PPK[1] ^ TK16( (i & 1) + 4 ) );
        PPK[3] += _S_( PPK[2] ^ TK16( (i & 1) + 6 ) );
        PPK[4] += _S_( PPK[3] ^ TK16( (i & 1) + 0 ) ) + i;
    }

    PPK[5] = PPK[4] + IV16;

    PPK[0] += _S_( PPK[5] ^ TK16(0) );
    PPK[1] += _S_( PPK[0] ^ TK16(1) );
    PPK[2] += _S_( PPK[1] ^ TK16(2) );
    PPK[3] += _S_( PPK[2] ^ TK16(3) );
    PPK[4] += _S_( PPK[3] ^ TK16(4) );
    PPK[5] += _S_( PPK[4] ^ TK16(5) );

    PPK[0] += ROTR1( PPK[5] ^ TK16(6) );
    PPK[1] += ROTR1( PPK[0] ^ TK16(7) );
    PPK[2] += ROTR1( PPK[1] );
    PPK[3] += ROTR1( PPK[2] );
    PPK[4] += ROTR1( PPK[3] );
    PPK[5] += ROTR1( PPK[4] );

    key[0] =   HI8( IV16 );
    key[1] = ( HI8( IV16 ) | 0x20 ) & 0x7F;
    key[2] =   LO8( IV16 );
    key[3] =   LO8( (PPK[5] ^ TK16(0) ) >> 1);

    for( i = 0; i < 6; i++ )
    {
        key[4 + ( 2 * i)] = LO8( PPK[i] );
        key[5 + ( 2 * i)] = HI8( PPK[i] );
    }

    return 0;
}

void
decrypt_tkip( u_char *bytes, int len, u_char TK1[16] )
{
    u_char K[16];

    calc_tkip_ppk( bytes, len, TK1, K );

    return( wep_decrypt( bytes + 8, K, 16, len - 8 ) );
}		

void *
pre_encrypt( void *arg )
{
	int status;
	u_char pmk[40];
	u_char key[40];
	AP_info *cur = NULL;
	frame_t *frame = NULL;
	stage_t *stage = ( stage_t * )arg;

	while(1) {
		status = pthread_mutex_lock( &stage->mutex );	
		if( status ) {
			user_exit( "Cannot lock mutex!" );	
		}

		while( !stage->is_ready ) {
			status = pthread_cond_wait(	&stage->cond_is_ready,
							&stage->mutex );
			if( status ) {
				user_exit( "Cannot wait!" );
			}
		}

		frame = stage->frame;

		if( frame != NULL ) {
			status = pthread_mutex_lock( &AP_list->lock );
			cur = AP_list->cur;
			status = pthread_mutex_unlock( &AP_list->lock );

			if( WEP_ENCRYPT  == cur->encrypt ) {

				merge_iv( frame->bytes, frame->len, key );	
				memmove( frame->bytes, &( frame->bytes[4] ), 
														frame->len -4 );
				wep_decrypt( frame->bytes, key,	
								frame->len - 4,
								IV_LEN + ( user->passwd_len ) / 2 );

				//analyse_flow( frame );

			} else if( WPA_ENCRYPT == cur->encrypt ) {
				
				wpa->valid_ptk = calc_ptk( pmk );

				if( TKIP == wpa->keyver ) {

					decrypt_tkip( frame->bytes, frame->len, 
										wpa->ptk + 32 );		
				} else {
  			//		decrypt_ccmp( frame->bytes, frame_len,
  			//						wpa->ptk + 32 );
				}
			} 
		}

		stage->is_ready = 0;
		stage->is_finished = 1;
	
		status = pthread_cond_signal( &stage->cond_is_finished );
		if( status ) {
			user_exit( "Cannot send signal to pthread!" );
		}
		status = pthread_mutex_unlock( &stage->mutex );
		if( status ) {
			user_exit( "Cannot unlock mutex!" );	
		}
	}
	return NULL;
}

