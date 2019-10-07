#include <stdio.h>
#include <iostream>
#include <string.h>
#include <math.h>
#include <map>            // std::map
#include <vector>         // std::vector 
#include <sys/time.h>     // gettimeofday
#include <stack>          // std::stack
#include <pbc.h>
#include <pbc_test.h>

#include "AES.h"
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rand.h>



#define CAL_REPEAT  10
#define PATHIDS_MAXMUM_LEN 5000

using namespace std;




class Param
{
public:
    pairing_t pairing;
    element_t p;
    element_t q;
    element_t g;
    element_t h;
    element_t gt;
    element_t R0;
    element_t R1;
    unsigned char aes_key[32];

    Param()
    {
        RAND_bytes(aes_key, 32);
        pbc_param_t param_t;
        mpz_t p_t, q_t, N_t;
        mpz_init(p_t);
        mpz_init(q_t);
        mpz_init(N_t);

        Gena1param(param_t, p_t, q_t, N_t);
        pairing_init_pbc_param(pairing, param_t);
        element_init_G1(g, pairing);
        element_init_G2(h, pairing);
        element_init_GT(gt, pairing);
        element_init_Zr(p, pairing);
        element_init_Zr(q, pairing);
        element_init_Zr(R0, pairing);
        element_init_Zr(R1, pairing);

        element_random(g);
        element_random(R0);
        element_random(R1);
        element_pairing(gt, g, g); // gt = e(g,g)
        element_set_mpz(q, q_t);
        element_set_mpz(p, p_t);
        element_pow_zn(h, g, q);

        mpz_clear(p_t);
        mpz_clear(q_t);
        mpz_clear(N_t);
    }
    ~Param()
    {
        element_clear(p);
        element_clear(q);
        element_clear(gt);
        element_clear(R0);
        element_clear(R1);
        element_clear(g);
        element_clear(h);
    }
    void Gena1param(pbc_param_t &param_t, mpz_t &p_t, mpz_t &q_t, mpz_t &N_t)
    {
        pbc_mpz_randomb(p_t, 512);
        pbc_mpz_randomb(q_t, 512);
        mpz_nextprime(p_t, p_t);
        mpz_nextprime(q_t, q_t);
        mpz_mul(N_t, p_t, q_t);
        pbc_param_init_a1_gen(param_t, N_t);
        return;
    }
};

int Hash(const char * algo, const char * input, unsigned int input_length, unsigned char * &output, unsigned int &
         output_length)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD * md = EVP_get_digestbyname(algo);
    if(!md) {
        printf("Unknown message digest algorithm: %s\n", algo);
        return -1;
    }

    output = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    memset(output, 0, EVP_MAX_MD_SIZE);

    EVP_MD_CTX_init(ctx);
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input, input_length);
    EVP_DigestFinal_ex(ctx, (unsigned char *)output, &output_length);
    EVP_MD_CTX_destroy(ctx);
    return 0;
}


int CalExponent(const long long level, const string &info, element_t &hash_exp)
{

    string hash_input = to_string(level);
    hash_input = info + hash_input;

    unsigned char * hash_output = NULL;
    unsigned int hash_output_size = 0;

    Hash("sha512", hash_input.c_str(), hash_input.size(), hash_output, hash_output_size);

    element_from_hash(hash_exp, hash_output, hash_output_size);
    free(hash_output);
}


int GenRandomVector(const int &len, string &binary_array)
{
    binary_array.resize(len);
    for (int i = 0; i < len; i++) {
        if(rand()%2 == 0)
            binary_array[i] = '0';
        else
            binary_array[i] = '1';
    }
    return 0;
}

int GenFilevector(int file_number, int dictionary_size, vector<string> &file_vector_list)
{
    string binary_array;
    srand (time(NULL));

    for (int i = 0; i < file_number; i++) {
        GenRandomVector(dictionary_size, binary_array);
        (file_vector_list).push_back(binary_array);
    }
    return 0;
}


/*
    1. 根据随机数来确定左右child是否交换位置(暂时不用做)
    1. 计算enc_tag: e(g,g)^{H(R||i)q}
*/
int BuildEncTag(Param &param, int dictionary_size, element_t (*enc_taglist)[2])
{
    for(int i = 0; i < dictionary_size; i++) {
        element_t hash_output;
        element_init_Zr(hash_output, param.pairing);
        // left
        CalExponent(i, "0" , hash_output); // H(R||level)
        element_mul(hash_output, hash_output, param.q); //  H(R||level)q
        element_pow_zn(enc_taglist[i][0], param.gt, hash_output); //e(g,g)^{H(R||level)q}

        // right
        CalExponent(i, "1", hash_output); // H(R||level)
        element_mul(hash_output, hash_output, param.q);
        element_pow_zn(enc_taglist[i][1], param.gt, hash_output); //e(g,g)^{H(R||level)q}
        element_clear(hash_output);
    }

    return 0;
}

/*
    1. 遍历 file_vector_list 中所有 file vector string
    2. for each file vector string, insert to pathids
        - key 值设置为 file vector, value 值设置为 file 序号.
        - 确定 file vector 对应的位置是否已经有值了, 如果有了则取出来级联后再插入
    3. 再遍历一遍 file_vector_list, 把所有 key 对应的 value 进行 AES 加密 (可以暂时不做)
*/
int BuildPathids(const Param &param,
                 const vector<string> &file_vector_list,
                 map<string, string> &pathids)
{
    map<string, string>::iterator it;
    long long file_id = 1;
    string temp_id;

    // store all the vectors in file_vector_list to pathids
    for(int i =0; i < file_vector_list.size(); i++) {
        it = pathids.find(file_vector_list[i]);
        if(it != pathids.end()) {
            temp_id = it->second + "," + to_string(file_id);
            pathids.erase(it);
            pathids[file_vector_list[i]] = temp_id;
        } else
            pathids[file_vector_list[i]] = to_string(file_id);
        file_id++;
    }

    return 0;
}

// Functionality: 
// Insert all the elements in file_vector_list to pathids, add dummy, and encrypt the pathids.
int BuildPathids(const Param &param,
                 const vector<string> &file_vector_list,
                 const long pathids_size,
                 unsigned char (*pathids)[PATHIDS_MAXMUM_LEN])
{
    unsigned short file_id = 1;
    int encrypted_len = 2 * sizeof(file_id) * file_vector_list.size() / pathids_size;
    char iv[AES_BLOCK_SIZE];
    int pathids_offset[pathids_size]; // offsets for each element in pathids
    // Add dummy to each element in pathids. By default, we add 1000 bytes of '#' for each id-set.
    for(int i = 0; i < pathids_size; i++)
        memset(pathids[i], '#', encrypted_len);

    // generate and store iv for each element in pathids
    for(int i = 0; i < pathids_size; i++) {
        RAND_bytes((unsigned char*)iv, AES_BLOCK_SIZE);
        memcpy(pathids[i], iv, AES_BLOCK_SIZE);
        pathids_offset[i] = AES_BLOCK_SIZE;
    }

    // store all the elements in file_vector_list to pathids
    long order;
//    printf("file_vector_list.size: %d ", file_vector_list.size());
    for(int i = 0; i < file_vector_list.size(); i++) {
//        printf("%d ", file_id);
        order = stoi(file_vector_list[i], NULL, 2);
        memcpy(pathids[order] + pathids_offset[order], &file_id, sizeof(file_id));
        pathids_offset[order] += sizeof(file_id);
        file_id++;
    }

    
    /* Encrypt the plaintext */
    int ciphertext_len;
    for(int i = 0; i < pathids_size; i++){
        ciphertext_len = AES_encrypt(pathids[i] + AES_BLOCK_SIZE, encrypted_len - 32, 
                            (unsigned char *) param.aes_key, pathids[i], pathids[i] + AES_BLOCK_SIZE);
    }
        
//    /* Decrypt the ciphertext */
//    int decryptedtext_len;
//    for(int i = 0; i < pathids_size; i++){
//        decryptedtext_len = AES_decrypt(pathids[i] + AES_BLOCK_SIZE, ciphertext_len, 
//                            (unsigned char *) param.aes_key, pathids[i], pathids[i] + AES_BLOCK_SIZE);
//    }
//
//    /* print ids */
//    for(int i = 0 ; i < pathids_size; i++){
//        printf("pathid[%d]: ", i);
//        for(int j = AES_BLOCK_SIZE; j < pathids_offset[i]; j += sizeof(file_id)){
//            printf("%hd ", *(unsigned short *)(pathids[i] + j));
//        }
//        printf("\n");
//    }

    return 0;
}



// Functionality: Randomly initialize query_vector and encrypt it to enc_query_vector: m --> g^{H(m||c)+pr}
// Input: param, dictionary_size, wildcard_size
// Output: wildcard_offset, enc_query_vector

int GenQueryVector(Param &param,
                   const int &dictionary_size,
                   const int &wildcard_size,
                   vector<int> &wildcard_offset,
                   element_t *enc_query_vector)
{
    string query_vector;
    element_t exp_value, r;

    // 随机生成 query_vector
    GenRandomVector(dictionary_size, query_vector);

    // 随机选取 wildcard_size 个位置当作 wildcard keyword, 将位置存储在 wildcard_offset 中.
    int select = wildcard_size, remaining = dictionary_size;
    for (int i = 0; i < dictionary_size; i++) {
        if((rand() % remaining) < select) {
            wildcard_offset.push_back(i);
            select--;
        }
        remaining--;
    }

    // 将 query_vector 的内容加密后存储到 enc_query_vector 中
    element_init_Zr(exp_value, param.pairing);
    element_init_Zr(r, param.pairing);
    element_random(r);
    for(int i = 0; i < query_vector.size(); i++) {
        if(query_vector[i] == '0') {
            CalExponent(i, "0", exp_value); // exp_value = H('0'||i)
        } else {
            CalExponent(i, "1", exp_value); // exp_value = H('0'||i)
        }
        element_mul(r, r, param.p); // r = pr
        element_add(exp_value, r, exp_value); // exp_value = H('0'||i) + pr
        element_pow_zn(enc_query_vector[i], param.g, exp_value);
    }
    element_clear(exp_value);
    element_clear(r);
    return 0;
}


//    Functionality: Find all the path vector
//    Input: enc_query_vector, wildcard_offset, dictioanry_size, enc_taglist
//    Ouput: None

int Search(Param &param,
           const int &dictionary_size,
           vector<int> &wildcard_offset,
           element_t *enc_query_vector,
           element_t (*enc_taglist)[2])
{
    vector<string> copy_path_set;
    element_t enc_tag;
    element_init_GT(enc_tag, param.pairing);

    // 遍历 enc_taglist, 确认满足 query 的第一个 path vector
    string path_vector(dictionary_size, '0');
    for(int i = 0, j = 0; i < dictionary_size; i++) {
        if(j < wildcard_offset.size() && wildcard_offset[j] == i) {
            j++;
        } else {
            element_pairing(enc_tag, enc_query_vector[i], param.h); // enc_tag = e(g^{H()+pr),h)
            if(element_cmp(enc_taglist[i][0], enc_tag) != 0)
                path_vector[i] = '1';
            else
                path_vector[i] = '0';
        }
    }


    // 通过在上一个path_vector位置来计算下一个path_vector的值, 不需要存储所有已经找到的path_vector
    while(true) {
        int i;
        // 通过在上一个path_vector的wildcard位置上+1来找到下一个path_vector(需要考虑进位)
        for(i = 0; i < wildcard_offset.size(); i++) {
            if(path_vector[wildcard_offset[i]] == '0') {
                path_vector[wildcard_offset[i]] = '1';
                break;
            } else {
                path_vector[wildcard_offset[i]] = '0';
            }
        }
        // 如果上一个path_vector的所有wildcard位置的值都是1, 则已经遍历了所有的path_vector了
        if(i == wildcard_offset.size())
            break;
//        cout << path_vector << endl;
    }

    element_clear(enc_tag);
    return 0;
}

// Test for oursourcing files
void OutsourceFileTest()
{
    int DICTIONARY_SIZE = 10;
    const long pathids_size = pow(2, DICTIONARY_SIZE);
    int wildcard_size = 0;
    int files_size = 0;
    int divide_num = 1;
    struct timeval time1,time2;
    element_t enc_taglist[DICTIONARY_SIZE][2];   // to store encrypted tags
    unsigned char pathids[pathids_size][PATHIDS_MAXMUM_LEN]; // to store encrypted id-sets
    vector<string> file_vector_list;             // to store all the file vector in file collection
    element_t enc_query_vector[DICTIONARY_SIZE]; // encrypted query vector
    vector<int> wildcard_offset;                 // to identify the locations of wildcard keywords in query vector
    float evaluate_time = 0;
    string dummy_id;
    Param param;

    cout << "d: " << DICTIONARY_SIZE << ", " << "divide_num: " << divide_num << endl;

    for(int i = 0; i < DICTIONARY_SIZE; i++)
        for(int j = 0; j < 2; j++)
            element_init_GT(enc_taglist[i][j], param.pairing);

    for(int i = 0; i < DICTIONARY_SIZE; i++)
        element_init_G1(enc_query_vector[i], param.pairing);

    for(files_size = 1; files_size <= 6; files_size++) {
        
        // file vector generation
        GenFilevector(files_size * 100000 / divide_num, DICTIONARY_SIZE, file_vector_list);
    
        for (int j = 0; j < CAL_REPEAT; j++) {

            gettimeofday(&time1,NULL);

            // build encrypted tag
            BuildEncTag(param, DICTIONARY_SIZE, enc_taglist);
        
            // build path-ids
            BuildPathids(param, file_vector_list, pathids_size, pathids);
            
            gettimeofday(&time2,NULL);

            evaluate_time += (time2.tv_sec-time1.tv_sec)+((double)(time2.tv_usec-time1.tv_usec))/1000000;

//            for(int z = 0; z < pathids_size; z++)
//                pathids[z].clear();
        }
        printf("evaluate_time: %f\n", divide_num * evaluate_time / CAL_REPEAT);
        evaluate_time = 0;

        vector<string>().swap(file_vector_list);
    }

}


// Test for basic keyword query
void QueryTest1()
{
    int DICTIONARY_SIZE = 10;
    const long pathids_size = pow(2, DICTIONARY_SIZE);
    int wildcard_size = 0;
    int files_size = 0;
    struct timeval time1,time2;
    Param param;
    element_t enc_taglist[DICTIONARY_SIZE][2];   // to store encrypted tag array
    unsigned char pathids[pathids_size][PATHIDS_MAXMUM_LEN];                // to store encrypted path-ids array
    vector<string> file_vector_list;             // to store all the file vector in file collection
    element_t enc_query_vector[DICTIONARY_SIZE]; // encrypted query vector
    vector<int> wildcard_offset;                 // to identify the locations of wildcard keywords in query vector
    float evaluate_time = 0;

    // Initial all the elements in the encrypted tag array
    for(int i = 0; i < DICTIONARY_SIZE; i++)
        for(int j = 0; j < 2; j++)
            element_init_GT(enc_taglist[i][j], param.pairing);

    // Initial all the elements in the encrypted query vector
    for(int i = 0; i < DICTIONARY_SIZE; i++)
        element_init_G1(enc_query_vector[i], param.pairing);


    for(files_size = 1; files_size <= 6; files_size++) {
        cout << files_size * 10000 << " ";

        // file vector generation
        GenFilevector(files_size * 10000, DICTIONARY_SIZE, file_vector_list);

        // build encrypted tag
        BuildEncTag(param, DICTIONARY_SIZE, enc_taglist);

        // build path-ids
        BuildPathids(param, file_vector_list, pathids_size, pathids);

        for (int j = 0; j < CAL_REPEAT; j++) {
            gettimeofday(&time1,NULL);

            // Generate encrypted query vector
            GenQueryVector(param, DICTIONARY_SIZE, wildcard_size, wildcard_offset, enc_query_vector);

            // Search
            Search(param,  DICTIONARY_SIZE, wildcard_offset, enc_query_vector, enc_taglist);

            gettimeofday(&time2,NULL);

            evaluate_time += (time2.tv_sec-time1.tv_sec)+((double)(time2.tv_usec-time1.tv_usec))/1000000;

            vector<int>().swap(wildcard_offset);
        }
        printf("%f\n", evaluate_time/CAL_REPEAT);
        evaluate_time = 0;

        vector<string>().swap(file_vector_list);
    }
}


// Test for wildcard keyword query
void QueryTest2()
{
    int DICTIONARY_SIZE = 10;
    const long pathids_size = pow(2, DICTIONARY_SIZE);
    int wildcard_size = 0;
    int files_size = 6;
    struct timeval time1,time2;
    Param param;
    element_t enc_taglist[DICTIONARY_SIZE][2];   // to store encrypted tag array
    unsigned char pathids[pathids_size][PATHIDS_MAXMUM_LEN];               // to store encrypted path-ids array
    vector<string> file_vector_list;             // to store all the file vector in file collection
    element_t enc_query_vector[DICTIONARY_SIZE]; // encrypted query vector
    vector<int> wildcard_offset;                 // to identify the locations of wildcard keywords in query vector
    float evaluate_time = 0;

    for(int i = 0; i < DICTIONARY_SIZE; i++)
        for(int j = 0; j < 2; j++)
            element_init_GT(enc_taglist[i][j], param.pairing);

    for(int i = 0; i < DICTIONARY_SIZE; i++)
        element_init_G1(enc_query_vector[i], param.pairing);


    for(wildcard_size = 0; wildcard_size <= DICTIONARY_SIZE; wildcard_size++) {
        cout << wildcard_size << " ";
        // file vector generation
        GenFilevector(files_size * 10000, DICTIONARY_SIZE, file_vector_list);

        // build encrypted tag
        BuildEncTag(param, DICTIONARY_SIZE, enc_taglist);

        // build path-ids
        BuildPathids(param, file_vector_list, pathids_size, pathids);

        for (int j = 0; j < CAL_REPEAT; j++) {
            gettimeofday(&time1,NULL);

            // Generate encrypted query vector
            GenQueryVector(param, DICTIONARY_SIZE, wildcard_size, wildcard_offset, enc_query_vector);

            // Search
            Search(param,  DICTIONARY_SIZE, wildcard_offset, enc_query_vector, enc_taglist);

            gettimeofday(&time2,NULL);

            evaluate_time += (time2.tv_sec-time1.tv_sec) + ((double)(time2.tv_usec-time1.tv_usec))/1000000;

            vector<int>().swap(wildcard_offset);
        }
        printf("%f\n", evaluate_time/CAL_REPEAT);
        evaluate_time = 0;

        vector<string>().swap(file_vector_list);
    }
}


int main(int argc, char * argv[])
{
    OutsourceFileTest();
//    QueryTest2();
    
    return 0;
}


