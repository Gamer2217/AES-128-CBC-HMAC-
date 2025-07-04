#include "AES.h"

void add_round_key(uint8_t input1[4][4], uint8_t input2[4][4], uint8_t result[4][4]){
        for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
        result[i][j]=input1[i][j]^input2[i][j];
                }
        }
}

uint8_t gf8_multiply(uint8_t input1 , uint8_t input2){
uint8_t result=0;
        while(input1){
        switch(input1 & 1){
                case 1:
                result ^= input2;
                break;

                default:
                break;
                }

        switch(input2 & 0x80 ? 1 : 0){
                case 1:
                input2=(input2<<1) ^ 0x1b;
                break;

                default:
                input2 <<= 1;
                break;
                }
        input1 >>=1;
        }
        return result;
}

uint8_t gf8_inverse(uint8_t input){
        if(input == 0){
        return 0;
        }
        for(int i=0; i<256; i++){
        if(gf8_multiply(input, i)==1){
        return i;
                }
        }
        return 0;
}

uint8_t affine(uint8_t b){
    uint8_t res = b ^ ((b << 1) | (b >> 7));
    res ^= ((b << 2) | (b >> 6));
    res ^= ((b << 3) | (b >> 5));
    res ^= ((b << 4) | (b >> 4));
    return (res ^ 0x63) & 0xFF;
}

void s_box_maker(uint8_t sbox[16][16]){
        uint8_t result=0;
        for(int i=0; i<256; i++){
        result=gf8_inverse((uint8_t)i);
        result=affine(result);
        sbox[i / 16][i % 16]=result;
        }
}

void s_box_encryption(uint8_t input_text[4][4] , uint8_t sbox[16][16], uint8_t result[4][4]){
        for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
        int new_index1=(input_text[i][j]>>4) & 0x0F;
        int new_index2=input_text[i][j] & 0x0F;
        result[i][j]=sbox[new_index1][new_index2];
        }
}

}

void shift_rows(uint8_t input[4][4],uint8_t output[4][4]){
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            output[r][c] = input[r][(c + r) % 4];
        }
    }
}

void mix_columns(uint8_t input[4][4], uint8_t matrix[4][4], uint8_t result[4][4]){
        uint8_t temp[4];
        for(int i=0;i<4;i++){
        temp[0]=input[0][i];
        temp[1]=input[1][i];
        temp[2]=input[2][i];
        temp[3]=input[3][i];

        result[0][i]=gf8_multiply(temp[0],matrix[0][0])^gf8_multiply(temp[1],matrix[0][1])^gf8_multiply(temp[2],matrix[0][2])^gf8_multiply(temp[3],matrix[0][3]);
        result[1][i]=gf8_multiply(temp[0],matrix[1][0])^gf8_multiply(temp[1],matrix[1][1])^gf8_multiply(temp[2],matrix[1][2])^gf8_multiply(temp[3],matrix[1][3]);
        result[2][i]=gf8_multiply(temp[0],matrix[2][0])^gf8_multiply(temp[1],matrix[2][1])^gf8_multiply(temp[2],matrix[2][2])^gf8_multiply(temp[3],matrix[2][3]);
        result[3][i]=gf8_multiply(temp[0],matrix[3][0])^gf8_multiply(temp[1],matrix[3][1])^gf8_multiply(temp[2],matrix[3][2])^gf8_multiply(temp[3],matrix[3][3]);

        }
}

void key_expansion(uint8_t input_key[4][4], uint8_t round_keys[11][4][4], uint8_t sbox[16][16]){
const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            round_keys[0][i][j] = input_key[i][j];
    for (int round = 1; round < 11; round++) {
        uint8_t temp[4];
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[round - 1][i][3];
        }
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;
        for (int i = 0; i < 4; i++) {
            int row = (temp[i] >> 4) & 0x0F;
            int col = temp[i] & 0x0F;
            temp[i] = sbox[row][col];
        }
        temp[0] ^= Rcon[round];
        for (int i = 0; i < 4; i++) {
            round_keys[round][i][0] = round_keys[round - 1][i][0] ^ temp[i];
        }
        for (int col = 1; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                round_keys[round][row][col] =
                    round_keys[round - 1][row][col] ^ round_keys[round][row][col - 1];
            }
        }
    }
}

void iv_generator( uint8_t result[4][4]){
        uint8_t bufferr[16];
        ssize_t r=getrandom(bufferr,sizeof(bufferr),0);
        for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
        result[i][j]=bufferr[i * 4 + j];
                }
        }
}

void XOR_with_iv(uint8_t text[4][4], uint8_t iv[4][4] , uint8_t result[4][4]){
        for(int i=0;i<4;i++){
                for(int j=0;j<4;j++){
                result[i][j]=text[i][j] ^ iv[i][j];
                }
        }
}

void generate_HMAC(const uint8_t hmac_key[32],
                   const uint8_t *data,
                   size_t data_len,
                   uint8_t hmac_result[32]){
    unsigned int len = 0;

    unsigned char* result = HMAC(
        EVP_sha256(),
        hmac_key, 32,
        data, data_len,
        NULL, &len
    );

    if (result != NULL && len == 32) {
        memcpy(hmac_result, result, 32);
    } else {
        exit(1);
    }
}
void inv_s_box_maker(uint8_t sbox[16][16], uint8_t inv_sbox[16][16]){
    for (int i = 0; i < 256; i++) {
        uint8_t s = sbox[i / 16][i % 16];
        inv_sbox[s / 16][s % 16] = i;
    }
}

void s_box_decryption(uint8_t input_text[4][4] , uint8_t inv_sbox[16][16], uint8_t result[4][4]){
        for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
        int new_index1=(input_text[i][j]>>4) & 0x0F;
        int new_index2=input_text[i][j] & 0x0F;
        result[i][j]=inv_sbox[new_index1][new_index2];
        }
}

}


void inv_shift_rows(uint8_t input[4][4],uint8_t output[4][4]){
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            output[r][c] = input[r][(c - r + 4) % 4];
        }
    }
}

void inv_mix_columns(uint8_t input[4][4], uint8_t matrix[4][4], uint8_t result[4][4]){
        uint8_t temp[4];
        for(int i=0;i<4;i++){
        temp[0]=input[0][i];
        temp[1]=input[1][i];
        temp[2]=input[2][i];
        temp[3]=input[3][i];

        result[0][i]=gf8_multiply(temp[0],matrix[0][0])^gf8_multiply(temp[1],matrix[0][1])^gf8_multiply(temp[2],matrix[0][2])^gf8_multiply(temp[3],matrix[0][3]);
        result[1][i]=gf8_multiply(temp[0],matrix[1][0])^gf8_multiply(temp[1],matrix[1][1])^gf8_multiply(temp[2],matrix[1][2])^gf8_multiply(temp[3],matrix[1][3]);
        result[2][i]=gf8_multiply(temp[0],matrix[2][0])^gf8_multiply(temp[1],matrix[2][1])^gf8_multiply(temp[2],matrix[2][2])^gf8_multiply(temp[3],matrix[2][3]);
        result[3][i]=gf8_multiply(temp[0],matrix[3][0])^gf8_multiply(temp[1],matrix[3][1])^gf8_multiply(temp[2],matrix[3][2])^gf8_multiply(temp[3],matrix[3][3]);

        }
}

bool check_HMACs(const uint8_t *first_HMAC,const uint8_t *second_HMAC, size_t size){
	uint8_t result=0;
	for(size_t i=0;i<size;i++){
	result|=first_HMAC[i]^second_HMAC[i];
	}
	return result == 0;
}


int main() {
    char plaintext[10000];
    printf("[>] Write text to encrypt: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0';

    char key[100];
    printf("[>] Write key for encryption: ");
    scanf("%s", key);

    if (strlen(key) != 16) {
        printf("[!] Invalid size of key! Must be 16 bytes.\n");
        return 1;
    }

    uint8_t plaintext_table[4][4];
    uint8_t key_table[4][4];
    uint8_t sbox[16][16];
    s_box_maker(sbox);
    uint8_t round_keys[11][4][4];
    uint8_t iv_key[4][4];
    iv_generator(iv_key);
    uint8_t prev_cipher[4][4];
    memcpy(prev_cipher, iv_key, sizeof(prev_cipher));
    uint8_t hmac_key[32];
    getrandom(hmac_key, sizeof(hmac_key), 0);

    uint8_t mixcolumns_matrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    uint8_t inv_mixcolumns_matrix[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    };

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            key_table[j][i] = (uint8_t) key[i * 4 + j];

    key_expansion(key_table, round_keys, sbox);

    int len = strlen(plaintext);
    int pad_value = (len % 16 == 0) ? 16 : 16 - (len % 16);
    int mid = (len / 16) + 1; 

    uint8_t final_result[10000];
    memcpy(final_result, iv_key, 16);
    int block_ind = 0;

    for (int i = 0; i < mid; i++) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                int idx = i * 16 + r * 4 + c;
               plaintext_table[r][c] = (uint8_t) ((idx < len) ? plaintext[idx] : pad_value);
            }
        }

        uint8_t xor_plaintext[4][4];
        XOR_with_iv(plaintext_table, prev_cipher, xor_plaintext);

        uint8_t state[4][4], tmp1[4][4], tmp2[4][4], tmp3[4][4];
        add_round_key(xor_plaintext, round_keys[0], state);

        for (int round = 1; round < 10; round++) {
            s_box_encryption(state, sbox, tmp1);
            shift_rows(tmp1, tmp2);
            mix_columns(tmp2, mixcolumns_matrix, tmp3);
            add_round_key(tmp3, round_keys[round], state);
        }

        s_box_encryption(state, sbox, tmp1);
        shift_rows(tmp1, tmp2);
        add_round_key(tmp2, round_keys[10], state);

        memcpy(prev_cipher, state, sizeof(prev_cipher));
        memcpy(final_result + 16 + block_ind * 16, state, 16);
        block_ind++;
    }

    size_t data_len = 16 + block_ind * 16;
    uint8_t hmac_result[32];
    generate_HMAC(hmac_key, final_result, data_len, hmac_result);
    memcpy(final_result + data_len, hmac_result, 32);
    size_t total_len = data_len + 32;

    printf("[>] Encrypted + HMAC:\n");
    for (int i = 0; i < total_len; i++) {
        printf("%02x", final_result[i]);
    }
    printf("\n");


    uint8_t new_hmac_key[32];
    memcpy(new_hmac_key, hmac_key, 32);
    uint8_t new_hmac_result[32];
    generate_HMAC(new_hmac_key, final_result, data_len, new_hmac_result);
    bool auth = check_HMACs(hmac_result, new_hmac_result, 32);

    if (!auth) {
        printf("New HMAC generated badly\n");
        return 1;
    }

    printf("New HMAC generated correctly\n");

    uint8_t IV_key_copied[4][4];
    uint8_t text_for_decrypting[data_len - 16];
    uint8_t new_round_keys[11][4][4];
    uint8_t key_decrypting[4][4];
    uint8_t inv_sbox[16][16];
    uint8_t block[4][4];
    uint8_t state_decrypt[4][4];
    uint8_t temp1[4][4], temp2[4][4], temp3[4][4];
    uint8_t decrypted_text[data_len - 16];

    memcpy(IV_key_copied, final_result, 16);
    memcpy(text_for_decrypting, final_result + 16, data_len - 16);
    memcpy(key_decrypting, key_table, sizeof(key_decrypting));
    key_expansion(key_decrypting, new_round_keys, sbox);
    inv_s_box_maker(sbox, inv_sbox);

    int blocks_count = (data_len - 16) / 16;
    uint8_t previous_cipher_block[4][4];
    memcpy(previous_cipher_block, IV_key_copied, sizeof(previous_cipher_block));

    for (int i = 0; i < blocks_count; i++) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                block[r][c] = text_for_decrypting[i * 16 + r * 4 + c];

        add_round_key(block, new_round_keys[10], state_decrypt);
        inv_shift_rows(state_decrypt, temp1);
        s_box_decryption(temp1, inv_sbox, state_decrypt);

        for (int j = 9; j > 0; j--) {
            add_round_key(state_decrypt, new_round_keys[j], temp1);
            inv_mix_columns(temp1, inv_mixcolumns_matrix, temp2);
            inv_shift_rows(temp2, temp3);
            s_box_decryption(temp3, inv_sbox, state_decrypt);
        }

        add_round_key(state_decrypt, new_round_keys[0], temp1);
        memcpy(state_decrypt, temp1, sizeof(temp1));

        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state_decrypt[c][r] ^= previous_cipher_block[c][r];

        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                decrypted_text[i * 16 + r * 4 + c] = state_decrypt[r][c];

        memcpy(previous_cipher_block, block, sizeof(block));
    }

    size_t decrypted_data_len = data_len - 16;
    uint8_t padding_value = decrypted_text[decrypted_data_len - 1];
    bool valid_padding = true;
printf("[DEBUG] Last decrypted block:\n");
for (int i = 0; i < 16; i++) {
    printf("%02x ", decrypted_text[(data_len - 16) - 16 + i]);
}
printf("\n");

    if (padding_value < 1 || padding_value > 16 || padding_value > decrypted_data_len) {
        valid_padding = false;
    } else {
        for (size_t i = 0; i < padding_value; i++) {
            if (decrypted_text[decrypted_data_len - 1 - i] != padding_value) {
                valid_padding = false;
                break;
            }
        }
    }

    if (!valid_padding) {
        printf("[!] Incorrect padding value!\n");
        return 1;
    }

    size_t decrypted_len = decrypted_data_len - padding_value;
    printf("[<] Decrypted message:\n");
    for (size_t i = 0; i < decrypted_len; i++) {
        printf("%c", decrypted_text[i]);
    }
    printf("\n");

    return 0;
}



