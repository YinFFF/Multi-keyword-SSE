#include <stdio.h>
#include <iostream>
#include <string.h>
//#include <string>
//#include <algorithm>
#include <map>            // std::map
#include <vector>         // std::vector 
#include <sys/time.h>     // gettimeofday
#include <stack>          // std::stack
#include <pbc.h>
#include <pbc_test.h>   
#include <openssl/hmac.h> 
#include <openssl/aes.h>  

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
    Param(int argc, char **argv)
    {
        pbc_demo_pairing_init(pairing, argc, argv);//argc=2 
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
};

int Hash(const char * algo, const char * input, unsigned int input_length, unsigned char * &output, unsigned int &
output_length) {
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
    for (int i = 0; i < len; i++){
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
    
    for (int i = 0; i < file_number; i++){
        GenRandomVector(dictionary_size, binary_array);
        (file_vector_list).push_back(binary_array);
    }
    return 0;
}

/* 
    BGN param: N, p, q, paring, 
*/
int ParaInit(Param &param)
{
    
    element_t x, G_result;
    mpz_t p, q;
    char str_p[] = "18710564239506363321092569960941033175501872002955666105886502000859045353566431534422\
74784389381451138782393044065511003897348260788154400120068621506603";
    char str_q[] = "1234147128547783749790155689599873776350931607662809713546383033870826479012249234449696\
1203751788630377389045663123037968229636248199407408064269627081959";

    mpz_init(p);
    mpz_init(q);
    mpz_set_str (p, str_p, 10);
    mpz_set_str (q, str_q, 10);
    element_set_mpz(param.q, q);
    element_set_mpz(param.p, p);
    element_pow_zn(param.h, param.g, param.q); // h = g^q
    mpz_clear(p);
    mpz_clear(q);
    return 0;
}


/*
    1. 根据随机数来确定左右child是否交换位置(暂时不用做)
    1. 计算enc_tag: e(g,g)^{H(R||i)q}
*/
int BuildEncTag(Param &param, int dictionary_size, element_t (*enc_taglist)[2])
{
    element_t hash_input, hash_output;
    element_init_Zr(hash_output, param.pairing);

    for(int i = 0; i < dictionary_size; i++){ 
        // left
        CalExponent(i, "0" , hash_output); // H(R||level)
        element_mul(hash_output, hash_output, param.q); //  H()q
        element_pow_zn(enc_taglist[i][0], param.gt, hash_output); //e(g,g)^H()q
        
        // right
        CalExponent(i, "1", hash_output); // H(R||level)
        element_mul(hash_output, hash_output, param.q);
        element_pow_zn(enc_taglist[i][1], param.gt, hash_output); //e(g,g)^H()q
    }

    element_clear(hash_output);
    return 0;
}

/*
    1. 遍历 file_vector_list 中所有 file vector string
    2. for each file vector string, insert to pathids 
        - key 值设置为 file vector, value 值设置为 file 序号.
        - 确定 file vector 对应的位置是否已经有值了, 如果有了则取出来级联后再插入
    3. 再遍历一遍 file_vector_list, 把所有 key 对应的 value 进行 AES 加密 (可以暂时不做)    
*/
int BuildPathids(const Param &param, const vector<string> &file_vector_list, map<string, string> &pathids)
{
    map<string, string>::iterator it;
    long long file_id = 1;
    string temp_id;

    // store all the vectors in file_vector_list to pathids
    for(int i =0; i < file_vector_list.size(); i++){
        it = pathids.find(file_vector_list[i]);
        if(it != pathids.end()){
            temp_id = it->second + "," + to_string(file_id);
            pathids.erase(it);
            pathids[file_vector_list[i]] = temp_id;
        }
        else
            pathids[file_vector_list[i]] = to_string(file_id);
        file_id++;
    }
    
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
    for (int i = 0; i < dictionary_size; i++){
        if((rand() % remaining) < select){
            wildcard_offset.push_back(i);
            select--;
        }
        remaining--;
    }
    
    // 将 query_vector 的内容加密后存储到 enc_query_vector 中
    element_init_Zr(exp_value, param.pairing);
    element_init_Zr(r, param.pairing);
    element_random(r);
    for(int i = 0; i < query_vector.size(); i++){
        if(query_vector[i] == '0'){
            CalExponent(i, "0", exp_value); // exp_value = H('0'||i)
        }else{
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
    for(int i = 0, j = 0; i < dictionary_size; i++){
        if(j < wildcard_offset.size() && wildcard_offset[j] == i){
            j++;
        }
        else{
            element_pairing(enc_tag, enc_query_vector[i], param.h); // enc_tag = e(g^{H()+pr),h)
            if(element_cmp(enc_taglist[i][0], enc_tag) != 0) 
                path_vector[i] = '1';
            else
                path_vector[i] = '0';
        }
    }

    // 找到所有的 path vectors, 存储在 path_set 中, 再统一打印出来 (path_set 可能会很大)
//    for(int i = 0; i < dictionary_size; i++)
//        if(wildcard_offset[i] == 1){            
//            copy_path_set = path_set;
//            for (int j = 0; j < copy_path_set.size(); j++)
//                copy_path_set[j][i] = '1';
//            path_set.insert(path_set.end(), copy_path_set.begin(), copy_path_set.end());
//        }       
//    
//    cout << "query : " << path_vector << endl;

    // 通过在上一个path_vector位置来找下一个path_vector, 不需要存储所有已经找到的path_vector   
    while(true){
        int i;
        // 通过在上一个path_vector的wildcard位置上+1来找到下一个path_vector(需要考虑进位)
        for(i = 0; i < wildcard_offset.size(); i++){
            if(path_vector[wildcard_offset[i]] == '0'){
                path_vector[wildcard_offset[i]] = '1';
                break;
            }else{
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
void OutsourceFileTest(int argc, char * argv[])
{
    int DICTIONARY_SIZE = 5;
    int wildcard_size = 0;
    int files_size = 0;
    struct timeval time1,time2;
    Param param(argc, argv);
    element_t enc_taglist[DICTIONARY_SIZE][2];   // to store encrypted tag array
    map<string, string> pathids;                 // to store encrypted path-ids array
    vector<string> file_vector_list;             // to store all the file vector in file collection
    element_t enc_query_vector[DICTIONARY_SIZE]; // encrypted query vector
    vector<int> wildcard_offset;                 // to identify the locations of wildcard keywords in query vector
    float evaluate_time = 0;
   
    for(int i = 0; i < DICTIONARY_SIZE; i++)
        for(int j = 0; j < 2; j++)
            element_init_GT(enc_taglist[i][j], param.pairing);
    
    for(int i = 0; i < DICTIONARY_SIZE; i++)  
        element_init_G1(enc_query_vector[i], param.pairing);


    for(files_size = 1; files_size <= 6; files_size++){
        
//        cout << files_size * 10000 << " ";
        
        // file vector generation
        GenFilevector(files_size * 10000, DICTIONARY_SIZE, file_vector_list); 

        // system initial
        ParaInit(param);
    
        int repeat_times = 50;
        for (int j = 0; j < repeat_times; j++){
            gettimeofday(&time1,NULL);

            // build encrypted tag
            BuildEncTag(param, DICTIONARY_SIZE, enc_taglist);

            // build path-ids
            BuildPathids(param, file_vector_list, pathids);  

            gettimeofday(&time2,NULL);

            evaluate_time += (time2.tv_sec-time1.tv_sec)+((double)(time2.tv_usec-time1.tv_usec))/1000000;
            
            map<string, string>().swap(pathids);
        }
        printf("%f\n", 4*evaluate_time/repeat_times);
        evaluate_time = 0;
        
        vector<string>().swap(file_vector_list);
    }
}



// Test for basic keyword query
void QueryTest1(int argc, char * argv[])
{
    int DICTIONARY_SIZE = 10;
    int wildcard_size = 0;
    int files_size = 0;
    struct timeval time1,time2;
    Param param(argc, argv);
    element_t enc_taglist[DICTIONARY_SIZE][2];   // to store encrypted tag array
    map<string, string> pathids;                 // to store encrypted path-ids array
    vector<string> file_vector_list;             // to store all the file vector in file collection
    element_t enc_query_vector[DICTIONARY_SIZE]; // encrypted query vector
    vector<int> wildcard_offset;                 // to identify the locations of wildcard keywords in query vector
    float evaluate_time = 0;
   
    for(int i = 0; i < DICTIONARY_SIZE; i++)
        for(int j = 0; j < 2; j++)
            element_init_GT(enc_taglist[i][j], param.pairing);
    
    for(int i = 0; i < DICTIONARY_SIZE; i++)  
        element_init_G1(enc_query_vector[i], param.pairing);


    for(files_size = 1; files_size <= 6; files_size++){
        
        cout << files_size * 10000 << " ";
        
        // file vector generation
        GenFilevector(files_size * 10000, DICTIONARY_SIZE, file_vector_list);
     
        // system initial
        ParaInit(param);

        // build encrypted tag
        BuildEncTag(param, DICTIONARY_SIZE, enc_taglist);

        // build path-ids
        BuildPathids(param, file_vector_list, pathids);  

        int repeat_times = 50;
        for (int j = 0; j < repeat_times; j++){
            gettimeofday(&time1,NULL); 
            
            // Generate encrypted query vector
            GenQueryVector(param, DICTIONARY_SIZE, wildcard_size, wildcard_offset, enc_query_vector);
            
            // Search
            Search(param,  DICTIONARY_SIZE, wildcard_offset, enc_query_vector, enc_taglist);
               
            gettimeofday(&time2,NULL); 

            evaluate_time += (time2.tv_sec-time1.tv_sec)+((double)(time2.tv_usec-time1.tv_usec))/1000000;

            vector<int>().swap(wildcard_offset);
        }
        printf("%f\n", evaluate_time/repeat_times);
        evaluate_time = 0;
        
        vector<string>().swap(file_vector_list);
        map<string, string>().swap(pathids);
    }
}


// Test for wildcard keyword query
void QueryTest2(int argc, char * argv[])
{
    int DICTIONARY_SIZE = 10;    
    int wildcard_size = 0;
    int files_size = 6;
    struct timeval time1,time2;
    Param param(argc, argv);
    element_t enc_taglist[DICTIONARY_SIZE][2];   // to store encrypted tag array
    map<string, string> pathids;                 // to store encrypted path-ids array
    vector<string> file_vector_list;             // to store all the file vector in file collection
    element_t enc_query_vector[DICTIONARY_SIZE]; // encrypted query vector
    vector<int> wildcard_offset;                 // to identify the locations of wildcard keywords in query vector
    float evaluate_time = 0;
   
    for(int i = 0; i < DICTIONARY_SIZE; i++)
        for(int j = 0; j < 2; j++)
            element_init_GT(enc_taglist[i][j], param.pairing);
    
    for(int i = 0; i < DICTIONARY_SIZE; i++)  
        element_init_G1(enc_query_vector[i], param.pairing);


    for(wildcard_size = 0; wildcard_size <= DICTIONARY_SIZE; wildcard_size++){
        cout << wildcard_size << " ";
        // file vector generation
        GenFilevector(files_size * 10000, DICTIONARY_SIZE, file_vector_list);
     
        // system initial
        ParaInit(param);

        // build encrypted tag
        BuildEncTag(param, DICTIONARY_SIZE, enc_taglist);

        // build path-ids
        BuildPathids(param, file_vector_list, pathids);  

        int repeat_times = 50;
        for (int j = 0; j < repeat_times; j++){
            gettimeofday(&time1,NULL); 
            
            // Generate encrypted query vector
            GenQueryVector(param, DICTIONARY_SIZE, wildcard_size, wildcard_offset, enc_query_vector);
            
            // Search
            Search(param,  DICTIONARY_SIZE, wildcard_offset, enc_query_vector, enc_taglist);
               
            gettimeofday(&time2,NULL); 

            evaluate_time += (time2.tv_sec-time1.tv_sec)+((double)(time2.tv_usec-time1.tv_usec))/1000000;

            vector<int>().swap(wildcard_offset);
        }
        printf("%f\n", evaluate_time/repeat_times);
        evaluate_time = 0;
        
        vector<string>().swap(file_vector_list);
        map<string, string>().swap(pathids);
    }
}




int main(int argc, char * argv[])
{
    OutsourceFileTest(argc, argv);
    return 0;
}
//int main(int argc, char * argv[])
//{
//
//	string data = "hello world";
//
//	unsigned char * hash = NULL;
//	unsigned int Hash_result_size = 0;
//    int ret;
//    ret = Hash("sha512", data.c_str(), data.size(), hash, Hash_result_size);	
//    if(0 == ret) {
//                ;//cout << "Algorithm succeeded!\n" << endl;
//    }else {
//        cout << "Algorithm failed!\n" << endl;
//        return 0;
//    }
//
//	cout << "Hash_result_size: " << Hash_result_size << endl;
//	cout << "hash:";
//	for(int i = 0; i < Hash_result_size; i++) {
//		printf("%-03x", (unsigned int)hash[i]);
//	}
//	cout << endl;
//	
//	if(hash) {
//		free(hash);
//		cout << "hash_result is freed!" << endl;
//	}
//
//	return 0;
//}

//int main(int argc, char * argv[])
//{
//        AES_KEY aes;  
//        unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16  
//        unsigned char iv[AES_BLOCK_SIZE];        // init vector  
//        unsigned char* input_string;  
//        unsigned char* encrypt_string;  
//        unsigned char* decrypt_string;  
//        unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)  
//        unsigned int i;  
//
//        // check usage  
//        if (argc != 2) {  
//            fprintf(stderr, "%s <plain text>\n", argv[0]);  
//            exit(-1);  
//        }  
//
//        
//        // set the encryption length  
//        len = 0;  
//        if ((strlen(argv[1]) + 1) % AES_BLOCK_SIZE == 0) {  
//            len = strlen(argv[1]) + 1;  
//        } else {  
//            len = ((strlen(argv[1]) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;  
//        }  
//
//        // set the input string  
//        input_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
//        if (input_string == NULL) {  
//            fprintf(stderr, "Unable to allocate memory for input_string\n");  
//            exit(-1);  
//        }  
//        strncpy((char*)input_string, argv[1], strlen(argv[1]));  
//
//        // Generate AES 128-bit key  
//        for (i=0; i<16; ++i) {  
//            key[i] = 32 + i;  
//        }  
//
//        // Set encryption key  
//        for (i=0; i<AES_BLOCK_SIZE; ++i) {  
//            iv[i] = 0;  
//        }  
//        if (AES_set_encrypt_key(key, 128, &aes) < 0) {  
//            fprintf(stderr, "Unable to set encryption key in AES\n");  
//            exit(-1);  
//        }  
//
//        // alloc encrypt_string  
//        encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));      
//        if (encrypt_string == NULL) {  
//            fprintf(stderr, "Unable to allocate memory for encrypt_string\n");  
//            exit(-1);  
//        }  
//
//        // encrypt (iv will change)  
//        AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);  
//
//        // alloc decrypt_string  
//        decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
//        if (decrypt_string == NULL) {  
//            fprintf(stderr, "Unable to allocate memory for decrypt_string\n");  
//            exit(-1);  
//        }  
//
//        // Set decryption key  
//        for (i=0; i<AES_BLOCK_SIZE; ++i) {  
//            iv[i] = 0;  
//        }  
//        if (AES_set_decrypt_key(key, 128, &aes) < 0) {  
//            fprintf(stderr, "Unable to set decryption key in AES\n");  
//            exit(-1);  
//        }  
//
//        // decrypt  
//        AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv,   
//                AES_DECRYPT);  
//
//        // print  
//        printf("input_string = %s\n", input_string);  
//        printf("encrypted string = ");  
//        for (i=0; i<len; ++i) {  
//            printf("%x%x", (encrypt_string[i] >> 4) & 0xf,   
//                    encrypt_string[i] & 0xf);      
//        }  
//        printf("\n");  
//        printf("decrypted string = %s\n", decrypt_string);  
//
//        return 0;  
//}

