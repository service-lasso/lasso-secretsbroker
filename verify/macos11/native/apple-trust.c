#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verification only: no keychain writes, no global trust changes. */
static SecCertificateRef load(const char *path) {
  FILE *f=fopen(path,"rb"); if(!f) return NULL;
  fseek(f,0,SEEK_END); long n=ftell(f); rewind(f);
  if(n<=0 || n>1048576){fclose(f);return NULL;}
  unsigned char *b=malloc(n); if(!b){fclose(f);return NULL;}
  size_t got=fread(b,1,n,f); fclose(f);
  CFDataRef d=got==(size_t)n?CFDataCreate(NULL,b,n):NULL; free(b);
  SecCertificateRef c=d?SecCertificateCreateWithData(NULL,d):NULL;
  if(d)CFRelease(d); return c;
}
int main(int argc,char **argv) {
  if(argc<6){fprintf(stderr,"host unix-time output-dir anchor-der-or-dash chain-der...\n");return 2;}
  CFMutableArrayRef certs=CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);
  for(int i=5;i<argc;i++){SecCertificateRef c=load(argv[i]);if(!c)return 3;CFArrayAppendValue(certs,c);CFRelease(c);}
  CFStringRef host=CFStringCreateWithCString(NULL,argv[1],kCFStringEncodingUTF8);
  SecPolicyRef policy=SecPolicyCreateSSL(true,host);CFRelease(host);
  SecTrustRef trust=NULL;OSStatus status=SecTrustCreateWithCertificates(certs,policy,&trust);
  CFRelease(certs);CFRelease(policy);if(status || !trust)return 4;
  CFDateRef date=CFDateCreate(NULL,strtod(argv[2],NULL)-978307200.0);
  status=SecTrustSetVerifyDate(trust,date);CFRelease(date);if(status)return 5;
  /* Explicit local anchor mode is separately classified from host roots. */
  if(strcmp(argv[4],"-")){
    SecCertificateRef a=load(argv[4]);if(!a)return 6;
    const void *v[]={a};CFArrayRef anchors=CFArrayCreate(NULL,v,1,&kCFTypeArrayCallBacks);
    status=SecTrustSetAnchorCertificates(trust,anchors);CFRelease(anchors);CFRelease(a);
    if(status || SecTrustSetAnchorCertificatesOnly(trust,true))return 7;
  }
  CFErrorRef error=NULL;Boolean accepted=SecTrustEvaluateWithError(trust,&error);
  printf("{\"accepted\":%s,\"anchorMode\":\"%s\",\"errorCode\":%ld,\"chainSha256\":[",accepted?"true":"false",strcmp(argv[4],"-")?"process-local":"host-roots",error?(long)CFErrorGetCode(error):0L);
  CFIndex count=SecTrustGetCertificateCount(trust);
  for(CFIndex i=0;i<count;i++){
    SecCertificateRef c=SecTrustGetCertificateAtIndex(trust,i);
    CFDataRef d=c?SecCertificateCopyData(c):NULL;if(!d)return 8;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(CFDataGetBytePtr(d),(CC_LONG)CFDataGetLength(d),digest);
    if(i)printf(",");printf("\"");for(int j=0;j<CC_SHA256_DIGEST_LENGTH;j++)printf("%02x",digest[j]);printf("\"");
    char path[4096];snprintf(path,sizeof(path),"%s/chain-%ld.der",argv[3],(long)i);
    FILE *f=fopen(path,"wb");if(!f)return 9;
    size_t n=fwrite(CFDataGetBytePtr(d),1,CFDataGetLength(d),f);fclose(f);
    if(n!=(size_t)CFDataGetLength(d))return 10;CFRelease(d);
  }
  printf("]}\n");if(error)CFRelease(error);CFRelease(trust);return 0;
}
