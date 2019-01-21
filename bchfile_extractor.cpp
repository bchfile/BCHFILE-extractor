#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wait.h>
#include <string.h>
#include <ctype.h>
#include <string>
#include <map>

#include "sha256.h"

using std::string;
using std::map;
using std::pair;

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned char BYTE;

//#define TESTNET

inline void StrToHex(BYTE *pbDest, BYTE *pbSrc, int nLen)
{
    char h1,h2;
    BYTE s1,s2;
    int i;

    for (i=0; i<nLen; i++)
    {
        h1 = pbSrc[2*i];
        h2 = pbSrc[2*i+1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9) 
        s1 -= 7;

        s2 = toupper(h2) - 0x30;
        if (s2 > 9) 
        s2 -= 7;

        pbDest[i] = s1*16 + s2;
    }
}

inline void StrToHexReverse(BYTE *pbDest, BYTE *pbSrc, int nLen)
{
    char h1,h2;
    BYTE s1,s2;
    int i;

    for (i=0; i<nLen; i++)
    {
        h1 = pbSrc[2*i];
        h2 = pbSrc[2*i+1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9) 
        s1 -= 7;

        s2 = toupper(h2) - 0x30;
        if (s2 > 9) 
        s2 -= 7;

        pbDest[nLen-1-i] = s1*16 + s2;
    }
}

inline void HexToStr(BYTE *pbDest, BYTE *pbSrc, int nLen)
{
    char    ddl,ddh;
    int i;

    for (i=0; i<nLen; i++)
    {
        ddh = 48 + pbSrc[i] / 16;
        ddl = 48 + pbSrc[i] % 16;
        if (ddh > 57) ddh = ddh + 39;   //7 for uppercase, 39 for lowercase
        if (ddl > 57) ddl = ddl + 39;
        pbDest[i*2] = ddh;
        pbDest[i*2+1] = ddl;
    }

    pbDest[nLen*2] = '\0';
}

inline void HexToStrReverse(BYTE *pbDest, BYTE *pbSrc, int nLen)
{
    char    ddl,ddh;
    int i;

    for (i=0; i<nLen; i++)
    {
        ddh = 48 + pbSrc[nLen-1-i] / 16;
        ddl = 48 + pbSrc[nLen-1-i] % 16;
        if (ddh > 57) ddh = ddh + 39;   //7 for uppercase, 39 for lowercase
        if (ddl > 57) ddl = ddl + 39;
        pbDest[i*2] = ddh;
        pbDest[i*2+1] = ddl;
    }

    pbDest[nLen*2] = '\0';
}

//----------------------------------------------------------------------------------
// convert hex var int(2B to 18B) to uint64
//----------------------------------------------------------------------------------
inline unsigned long int var2int64(char* hex_var, char *bytes) {
    unsigned char b[9];
    unsigned char s1, s2;
    int i;
    s1 = toupper(hex_var[0]) - 0x30;
    if (s1 > 9)
        s1 -= 7;
    s2 = toupper(hex_var[1]) - 0x30;
    if (s2 > 9)
        s2 -= 7;
    b[0] = s1*16 + s2;
    if (b[0] > 252) {
        switch (b[0]) {
            case 253: 
            for (i=1; i<3; i++) {
                s1 = toupper(hex_var[i*2]) - 0x30;
                if (s1 > 9) s1 -= 7;
                s2 = toupper(hex_var[i*2+1]) - 0x30;
                if (s2 > 9) s2 -= 7;
                b[i] = s1*16 + s2;
            }
            *bytes = 3;
            return (unsigned long int)*((unsigned short*)&b[1]);
            case 254: 
            for (i=1; i<5; i++) {
                s1 = toupper(hex_var[i*2]) - 0x30;
                if (s1 > 9) s1 -= 7;
                s2 = toupper(hex_var[i*2+1]) - 0x30;
                if (s2 > 9) s2 -= 7;
                b[i] = s1*16 + s2;
            }
            *bytes = 5;
            return (unsigned long int)*((unsigned int*)&b[1]);
            case 255: 
            for (i=1; i<9; i++) {
                s1 = toupper(hex_var[i*2]) - 0x30;
                if (s1 > 9) s1 -= 7;
                s2 = toupper(hex_var[i*2+1]) - 0x30;
                if (s2 > 9) s2 -= 7;
                b[i] = s1*16 + s2;
            }
            *bytes = 9;
            return (unsigned long int)*((unsigned long int*)&b[1]);
        }
    }
    else {
        *bytes = 1;
        return b[0];
    }
}

int cmd_run(const char* cmd, char* argv[], char* outstr)
{
    char buffer[65536] = { 0 };
    int len;
    int pfd[2];
    int status;
    pid_t pid;
 
    /* create pipe */
    if (pipe(pfd)<0)
        return -1;
 
    /* fork to execute external program or scripts */
    pid = fork();
    if (pid<0) {
        return 0;
    } else if (pid==0) { /* child process */
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[0]);
 
        /* execute CGI */
        execvp(cmd, argv);
        close(pfd[1]);
        exit(0);
    } else { /* parent process */
        close(pfd[1]);
 
        /* print output from CGI */
        while((len=read(pfd[0], buffer, 65536))>0) {
            memcpy(outstr, buffer, len);
            outstr += len;
        }
        outstr[0] = '\0';
 
        /* waiting for CGI */
        waitpid((pid_t)pid, &status, 0);
        close(pfd[0]);
    }
    return 0;
}

//----------------------------------------------------------------------------------
// get blockhash from block_num
//----------------------------------------------------------------------------------
void getblockhash(int block_num, char* blockhash) {
    char cmd[20] = "bitcoin-cli";
    char cmd2[30] = "getblockhash";
    char blocknum_str[20];
    sprintf(blocknum_str,"%d",block_num);
#ifdef TESTNET
    char cmd3[20] = "-testnet";
    char *argv2[5] = {cmd,cmd3,cmd2,blocknum_str,0};
#else
    char *argv2[4] = {cmd,cmd2,blocknum_str,0};
#endif
    cmd_run(argv2[0],&argv2[0],blockhash);
    blockhash[strlen(blockhash)-1] = 0;
}

//----------------------------------------------------------------------------------
// get blockcount
//----------------------------------------------------------------------------------
void getblockcount(int* blockcount) {
    char cmd[20] = "bitcoin-cli";
    char cmd2[30] = "getblockcount";
#ifdef TESTNET
    char cmd3[20] = "-testnet";
    char *argv2[4] = {cmd,cmd3,cmd2,0};
#else
    char *argv2[3] = {cmd,cmd2,0};
#endif
    char outputs[100];
    cmd_run(argv2[0],&argv2[0],outputs);
    outputs[strlen(outputs)-1] = 0;
    sscanf(outputs,"%d",blockcount);
}

//----------------------------------------------------------------------------------
// get txid of rawtx
//----------------------------------------------------------------------------------
void getrawtxid(char* rawtx, char* txid) {
    char cmd[20] = "bitcoin-tx";
    char cmd2[20] = "-txid";
#ifdef TESTNET
    char cmd3[20] = "-testnet";
    char *argv2[5] = {cmd,cmd3,cmd2,rawtx,0};
#else
    char *argv2[4] = {cmd,cmd2,rawtx,0};
#endif
    cmd_run(argv2[0],&argv2[0],txid);
    txid[strlen(txid)-1] = 0;
}

//----------------------------------------------------------------------------------
// get txid of rawtx faster
//----------------------------------------------------------------------------------
void getrawtxidfast(char* rawtx, char* txid) {
    int len = strlen(rawtx)/2;
    int i;
    BYTE tx[100000];        //100KB
    BYTE digest[32];
    StrToHex(tx, (BYTE*)rawtx, len);
    sha256_hash(digest, tx, len);
    sha256_hash(digest, digest, 32);
    HexToStrReverse((BYTE*)txid, digest, 32);
    txid[64] = 0;
}

typedef map<string, string> TX_MAP;
typedef map<string, int> BLKNUM_MAP;
char block_str[65000000];       //65MB

//----------------------------------------------------------------------------------
// get block txs from blockhash
//----------------------------------------------------------------------------------
void getblock(int blocknum, char* blockhash, TX_MAP* head_map, TX_MAP* data_map, BLKNUM_MAP* blocknum_map, int* blocksize) {
    char cmd[20] = "bitcoin-cli";
    char cmd2[20] = "getblock";
    char cmd3[20] = "false";
#ifdef TESTNET
    char cmd4[20] = "-testnet";
    char *argv2[6] = {cmd,cmd4,cmd2,blockhash,cmd3,0};
#else
    char *argv2[5] = {cmd,cmd2,blockhash,cmd3,0};
#endif
    cmd_run(argv2[0],&argv2[0],block_str);
    *blocksize = strlen(block_str);
    block_str[*blocksize-1] = 0;
    *blocksize = (*blocksize)/2;
    
    char* pos = block_str+160;  //skip the block head
    char* tx_pos;
    char int_len;
    unsigned long int tx_cnt, txin_cnt, txout_cnt, inscript_len, outscript_len;
    int i, j;
    tx_cnt = var2int64(pos, &int_len);  //Transactions Counter
    pos += int_len*2;
    for (j=0; j<tx_cnt; j++) {
        int tx_flag = 0;
        tx_pos = pos;
        pos += 4*2;     //skip tx version
        txin_cnt = var2int64(pos, &int_len);    //Inputs Counter
        pos += int_len*2;
        for (i=0; i<txin_cnt; i++) {
            pos += 36*2;    //skip Previous tx Hash and Previous Output Index
            inscript_len = var2int64(pos, &int_len);    //Inputs script length
            pos += int_len*2;
            pos += inscript_len*2+4*2;
        }
        txout_cnt = var2int64(pos, &int_len);   //Outputs Counter
        pos += int_len*2;
        for (i=0; i<txout_cnt; i++) {
            if (i==0) {
                if (!strncmp(pos,"0000000000000000",16)) {  //first output amount = 0, op_return found
                    char* op_return = pos+18;
                    char* op_return_data;
                    BYTE data_len;
                    char flag = 0;
                    if ((op_return[0]=='6') && (op_return[1]=='a')) {       //0x6a
                        if ((op_return[2]=='4') && (op_return[3]=='c')) {   //0x4c
                            StrToHex(&data_len, (BYTE*)&op_return[4], 1);       //get op_return data length
                            if (data_len > 75) {
                                op_return_data = &op_return[6];
                                flag = 1;
                            }
                            else {
                                printf ("Error OP_RETURN FOUND! data_len = %d\n", data_len);
                            }
                        }
                        else {  //1-75
                            StrToHex(&data_len, (BYTE*)&op_return[2], 1);       //get op_return data length
                            if (data_len >= 7) {
                                op_return_data = &op_return[4];
                                flag = 1;
                            }
                            else if ((data_len > 75) || (data_len==0)) {
                                printf ("Error OP_RETURN FOUND! data_len = %d\n", data_len);
                            }
                        }
                        if (flag) {
                            if (!strncmp(op_return_data, "42434846", 8)) {  //"BCHF"
                                if (!strncmp(op_return_data+8, "4d", 2)) {  //"M"
                                    //store TX to head_map
                                    tx_flag = 1;
                                }
                                else if ((!strncmp(op_return_data+8, "42", 2))      //"B"
                                       || !strncmp(op_return_data+8, "44", 2)) {    //"D"
                                    //store TX to data_map
                                    tx_flag = 2;
                                }
                            }
                        }
                    }
                }
            }
            pos += 8*2; //skip Amount of Output
            outscript_len = var2int64(pos, &int_len);   //Outputs script length
            pos += int_len*2;
            pos += outscript_len*2;
        }
        pos += 4*2; //Skip Lock Time
        if (tx_flag) {
            int tx_len = pos - tx_pos;
            char tx_str[200000];    //200KB
            char tx_id[70];
            memcpy(tx_str,tx_pos,tx_len);
            tx_str[tx_len]=0;
            getrawtxidfast(tx_str, tx_id);
            if (tx_flag == 1) {
                head_map->insert(pair<string,string>(tx_id,tx_str));    //insert TX to head_map
                blocknum_map->insert(pair<string,int>(tx_id,blocknum));
            }
            else if (tx_flag == 2) {
                data_map->insert(pair<string,string>(tx_id,tx_str));    //insert TX to data_map
            }
        }
    }
}

//----------------------------------------------------------------------------------
// decode rawtx
//----------------------------------------------------------------------------------
void decoderawtx(char* rawtx, char* decodetx) {
    char cmd[20] = "bitcoin-cli";
    char cmd2[30] = "decoderawtransaction";
#ifdef TESTNET
    char cmd3[20] = "-testnet";
    char *argv2[5] = {cmd,cmd3,cmd2,rawtx,0};
#else
    char *argv2[4] = {cmd,cmd2,rawtx,0};
#endif
    cmd_run(argv2[0],&argv2[0],decodetx);
    decodetx[strlen(decodetx)-1] = 0;
}

//----------------------------------------------------------------------------------
// decode rawtx faster
//----------------------------------------------------------------------------------
void decoderawtxfast(char* rawtx, BYTE* op_return_data, int* len) {
    char int_len;
    unsigned long int txin_cnt, txout_cnt, inscript_len, outscript_len;
    int i, j;
    int tx_flag = 0;
    char* pos = rawtx;
    pos += 4*2;     //skip tx version
    txin_cnt = var2int64(pos, &int_len);    //Inputs Counter
    pos += int_len*2;
    for (i=0; i<txin_cnt; i++) {
        pos += 36*2;    //skip Previous tx Hash and Previous Output Index
        inscript_len = var2int64(pos, &int_len);    //Inputs script length
        pos += int_len*2;
        pos += inscript_len*2+4*2;
    }
    txout_cnt = var2int64(pos, &int_len);   //Outputs Counter
    pos += int_len*2;
    if (!strncmp(pos,"0000000000000000",16)) {  //first output amount = 0, op_return found
        char* op_return = pos+18;
        char* op_return_data_str;
        BYTE data_len;
        char flag = 0;
        if ((op_return[0]=='6') && (op_return[1]=='a')) {       //0x6a
            if ((op_return[2]=='4') && (op_return[3]=='c')) {   //0x4c
                StrToHex(&data_len, (BYTE*)&op_return[4], 1);       //get op_return data length
                if (data_len > 75) {
                    op_return_data_str = &op_return[6];
                    flag = 1;
                }
                else {
                    printf ("Error OP_RETURN FOUND! data_len = %d\n", data_len);
                }
            }
            else {  //1-75
                StrToHex(&data_len, (BYTE*)&op_return[2], 1);       //get op_return data length
                if (data_len >= 7) {
                    op_return_data_str = &op_return[4];
                    flag = 1;
                }
                else if ((data_len > 75) || (data_len==0)) {
                    printf ("Error OP_RETURN FOUND! data_len = %d\n", data_len);
                }
            }
            if (flag) {
                StrToHex(op_return_data, (BYTE*)op_return_data_str, data_len);
                *len = data_len;
            }
        }
    }
    else {
        printf ("Error Transaction, no OP_RETURN data found.\n");
        *len = 0;
    }
}

//----------------------------------------------------------------------------------
// get filedata from data_map
//----------------------------------------------------------------------------------
void getfiledata(char* txid, TX_MAP* data_map, BYTE* filedata, size_t* filepos, unsigned int* cnt, bool* error) {
    TX_MAP::iterator iter;
    char decodetx[500000];      //500KB
    char in_txid[70];
    char* tmp;
    char* tmp2;
    int len;
    BYTE op_return_data[223];
    iter = data_map->find(txid);    //find tx
    if(iter != data_map->end()) {
        decoderawtxfast((char *)iter->second.c_str(), op_return_data, &len);
        if (op_return_data[4]=='D') {
            memcpy(filedata+(*filepos), &op_return_data[9], len-9);
            *filepos += len-9;
            (*cnt) ++;
            if (*cnt != *((unsigned int*)&op_return_data[5]))
                *error = 1;
        }
        else if (op_return_data[4]=='B'){
            char* pos = (char *)iter->second.c_str();
            pos += 4*2;     //skip tx version
            char int_len, inscript_len;
            int i, j;
            unsigned long int txin_cnt = var2int64(pos, &int_len);  //Inputs Counter
            pos += int_len*2;
            for (i=0; i<txin_cnt; i++) {
                for (j=0; j<32; j++) {
                    in_txid[62-j*2] = pos[j*2];
                    in_txid[63-j*2] = pos[j*2+1];
                }
                in_txid[64] = 0;
                getfiledata(in_txid, data_map, filedata, filepos, cnt, error);
                pos += 36*2;    //skip Previous tx Hash and Previous Output Index
                inscript_len = var2int64(pos, &int_len);    //Inputs script length
                pos += int_len*2;
                pos += inscript_len*2+4*2;
            }
        }
    }
}

void getfile(TX_MAP::iterator head, TX_MAP* data_map, BYTE* filedata, size_t* filelen,
             BYTE* digest, size_t *filesize, BYTE* filename) {
    char decodetx[500000];      //500KB
    char in_txid[70];
    char* tmp;
    char* tmp2;
    int len;
    unsigned int cnt;
    bool error = 0;
    BYTE op_return_data[223];
    BYTE size[8];
    
    decoderawtx((char *)head->second.c_str(), decodetx);    //decode tx
    tmp = strstr(decodetx, "\"vout\"");
    tmp = strstr(tmp, "OP_RETURN") + 10;
    tmp2 = strchr(tmp, '\"');
    len = (tmp2-tmp)/2;
    StrToHex(op_return_data, (BYTE*)tmp, len);
    memcpy(digest, op_return_data+7,32);
    memset(size,0,8);
    memcpy(size,op_return_data+43,5);
    *filesize = *(size_t*)size;
    memcpy(filename,op_return_data+48,160);
    
    tmp = strstr(decodetx, "\"vin\"");
    cnt = 0;
    while (1) {
        tmp = strstr(tmp, "\"txid\"");
        if (!tmp)
            break;
        tmp += 9;
        memcpy(in_txid,tmp,64);
        in_txid[64] = 0;
        getfiledata(in_txid, data_map, filedata, filelen, &cnt, &error);
    }
    printf ("\nPiece count = %d, Error = %d\n", cnt, error);
}

BYTE filedata[50000000];    //50MB
size_t filelen;
BYTE digest[32];
size_t filesize;
BYTE filename[160];

int main( int argc, char *argv[] ) {

    TX_MAP head_map, data_map;
    BLKNUM_MAP blocknum_map;
    int latest_block;
#ifdef TESTNET
    int begin_block = 1280172;
#else
    int begin_block = 561352;
#endif
    int block_num;
    char blockhash[70];
    char digest_str[65];
    char fname_save[100];
    int i = 0;
    FILE* fp;
    getblockcount(&latest_block);
    printf ("Usage: bchfile [begin_block_num [end_block_num]]\n");
    printf ("Eg: bchfile 561352 562352\n\n");
    if (argc >= 2) {
        int beginblock_arg = atoi(argv[1]);
        if ((beginblock_arg >= begin_block) && (beginblock_arg <= latest_block))
            begin_block = beginblock_arg;
        else {
            printf ("begin_block_num not in the correct range.\n");
            return 1;
        }
        if (argc == 3) {
            int endblock_arg = atoi(argv[2]);
            if ((endblock_arg >= begin_block) && (endblock_arg <= latest_block))
                latest_block = endblock_arg;
            else {
                printf ("end_block_num not in the correct range.\n");
                return 1;
            }
        }
    }
//  latest_block = 1280211;         //for debug
    unsigned long int totalblocksize = 0;
    int blocksize;
    
    printf ("Reading blocks from %d to %d ...\n", begin_block, latest_block);
    
    for (block_num = begin_block; block_num <= latest_block; block_num++) {
        getblockhash(block_num, blockhash);
        getblock(block_num, blockhash, &head_map, &data_map, &blocknum_map, &blocksize);
        totalblocksize += blocksize;
        if ((block_num % 10) == 0)
            printf ("Processing block %d, blocksize = %8d, totalsize = %12ld\n", block_num, blocksize, totalblocksize);
    }
    printf ("Reading blocks complete.\n");
    TX_MAP::iterator my_Itr;
    BLKNUM_MAP::iterator blknum_itr;

    printf ("Extracting files ...\n");
#ifdef TESTNET
    FILE* fp2 = fopen("Testnet_Bchfile_Summary", "w+");
#else
    FILE* fp2 = fopen("Bchfile_Summary", "w+");
#endif
    blknum_itr = blocknum_map.begin();
    for (my_Itr=head_map.begin(); my_Itr!=head_map.end(); ++my_Itr)
    {
        filelen = 0;
        filesize = 0;
        getfile(my_Itr, &data_map, filedata, &filelen, digest, &filesize, filename);
        HexToStr((BYTE *)digest_str, digest, 32);
        digest_str[64] = 0;
        
        sprintf(fname_save, "%d-%s", blknum_itr->second, my_Itr->first.c_str());
        fp = fopen(fname_save, "wb+");
        fwrite(filedata, filelen, 1, fp);
        fclose(fp);
        
        printf("blocknum = %d, filelen = %d, filesize = %d, digest = %s\n", blknum_itr->second, filelen, filesize, digest_str);
        fprintf(fp2, "blocknum = %d, filelen = %d, filesize = %d, digest = %s\n", blknum_itr->second, filelen, filesize, digest_str);
        printf("txID = %s\n", my_Itr->first.c_str());
        fprintf(fp2, "txID = %s\n", my_Itr->first.c_str());
        printf("filename = %s\n", filename);
        fprintf(fp2, "filename = %s\n\n", filename);
        blknum_itr++;
    }
    fclose(fp2);
#ifdef TESTNET
    printf("\nSummary stored in file Testnet_Bchfile_Summary.\n");
#else
    printf("\nSummary stored in file Bchfile_Summary.\n");
#endif

    return 0;
}
