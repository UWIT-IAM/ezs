/* ========================================================================
 * Copyright (c) 2006 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>

#include "ezs.h"

#define UC (unsigned char*)

static char *pnbytes(unsigned char *byt, int n)
{
   int i;
   char *buf, *p;
   buf = (char *) malloc(n*2+1);
   p = buf;
   if (n>64) n = 64;
   for (i=0;i<n;i++) {
      sprintf(p,"%2.2x", *byt);
      byt++;
      p += 2;
   }
   *p = '\0';
   return (buf);
}


main()
{
    char *p_in, *p_out;
    unsigned char *e;
    int in_l, out_l;
    int r, l;
    char *key = "The key";
    unsigned char *iv = NULL;
    FILE *f;
    unsigned char *mac;
    int macl;
    char *mac64;
    int mac64l;

    /* ezs_debug = 99; */
    EZS *E = ezs_new();

    if (!(f=fopen("crypt1.c", "r"))) {
       perror("crypt1.c");
       exit (1);
    }
    fseek(f, 0, SEEK_END); 
    in_l = ftell(f);
    fseek(f, 0, SEEK_SET); 
    p_in = (char*) malloc(in_l);
    r = fread(p_in, 1, in_l, f);
    fclose(f);
  
    r = ezs_crypt_init(E, key, strlen(key), &iv);
    printf("icrypt: r=%d, l=%d, bs=%d\n", r, in_l, EZS_BLOCKSIZE(E));

    e = UC malloc(in_l+EZS_BLOCKSIZE(E));
    r = ezs_crypt(E, EZS_ENCRYPT, e, &l, UC p_in, in_l);
    printf("ecrypt: r=%d, l=%d\n", r, l);

    p_out = (char*) malloc(l+EZS_BLOCKSIZE(E));
    r = ezs_crypt(E, EZS_DECRYPT, UC p_out, &out_l, e, l);
    printf("dcrypt: r=%d, l=%d\n", r, out_l);

    if (!(f=fopen("crypt1.out", "w"))) {
       perror("crypt1.out");
       exit (1);
    }
    fwrite(p_out, 1, out_l, f);
    fclose(f);

    /* generate a mac of the decrypted data */

    ezs_hmac(&mac, &macl, UC p_in, in_l, UC "thekey", 6);
    printf("mac (in=%d) = (out=%d) %s\n", in_l, macl, pnbytes(mac, macl));

    ezs_data_to_base64(&mac64, &mac64l, (void*)mac, macl);
    printf("Hash of \"crypt1.out\" is: %s\n", mac64);

    mac = NULL;
    ezs_base64_to_data((void**)&mac, &macl, mac64, mac64l);
    printf("mac (%d) %s\n", macl, pnbytes(mac, macl));
    
}
