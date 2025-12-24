#ifndef MD5_h
#define MD5_h

#include <Arduino.h>
#include <string.h>

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c
#define BLOCK_SIZE 16

typedef unsigned long MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;/**< MD5 context */

class MD5
{
public:
	/**
	 * class constructor.
	 * Does nothing.
	 */
	MD5();
	
	/** Created the MD5 hash from a string of characters on hex encoding.
	 * 
	 * 	It is one of the main function of this class.
	 *  Gets an pointer to a string, and hash it to MD5.
	 * 
	 *  @param *arg pointer to the string or array of characters.
	 *  @return a pointer containing the MD5digest
	 * 
	 */
	unsigned char* make_hash(const void *arg);
	
	/** Converts a digest to a string.
	 * 
	 * 	In order for tedigest to be readable and printed easyly, we need to conver it.
	 * 
	 * 	@param *digest pointer to the array that holds the digest
	 *  @param len integer defining the lengs of the output, usually 16 for MD5
	 *  @return poiner to the string that holds the String of the converted digest
	 */
	char* make_digest(const unsigned char *digest, int len);
	
	/** Automation function.
	 *  Gets a pointer to sequence of chars,
	 *  Then Hashes it, and converts it to a readable form,
	 * 
	 *  @param *arg pointer to the string that will be hashed.
	 *  @return pointer to the string that holds the string of the converted digest.
	 */
	char* md5(const void *arg);
	
	/** Main function of the HMAC-MD5.
	 *  gets the key and the text, and creates the HMAC-MD5 digest function.
	 *  in order to be pronted, it is required for the make_digest function to be called.
	 *  @code make_digest(digest,BLOCK_SIZE); @endcode
	 *  
	 *  @param *text pointer to the text that will be hashed.
	 *  @param text_len integet value of the length of the text.
	 *  @param *key pointer to the key that will be used in the HMAC process.
	 *  @param key_len integer value of the key length.
	 *  @param *digest pointer to the array that will hold the digest of this process
	 *  @return the digest in the memory block that the *digest is pointing.
	 */
	void hmac_md5(const void *text, int text_len,void *key, int key_len, unsigned char *digest);
	
	/** Main function of the HMAC-MD5.
	 *  gets the key and the text, and creates the HMAC-MD5 digest function in a readable format.
	 *  
	 *  @param *text pointer to the text that will be hashed.
	 *  @param text_len integet value of the length of the text.
	 *  @param *key pointer to the key that will be used in the HMAC process.
	 *  @param key_len integer value of the key length.
	 *  @return pointer that points to the digest in a readable format.
	 */
	char* hmac_md5(const void *text, int text_len,void *key, int key_len);
	
	/** This processes one or more 64-byte data blocks, but does NOT update the bit counters.  
	 *  There are no alignment requirements.
	 * 
	 *  @param *ctxBuf the ctx buffer that will be used
	 *  @param *data pointer to the data that will be processed
	 *  @param size size_t type, that hold the size
	 */
 	static const void *body(void *ctxBuf, const void *data, size_t size);
 	
 	/** Initialized the MD5 hashing process.
 	 *  this function must be called before MD5Update or MD5Final
	 * 
	 *  @param *ctxBuf the ctx buffer that will be used
	 */
	static void MD5Init(void *ctxBuf);
	
	
 	/** MD5Final finilized the Hashing process and creates the diggest.
	 *  This function must be called after MD5Init and MD5Update
	 *  @param *result pointer that will hold the digest.
	 *  @param *ctxBuf the ctx buffer that will be used
	 *  @return no return, the result is storesin the *result pointer
	 */
	static void MD5Final(unsigned char *result, void *ctxBuf);
	
	/** MD5Update adds data in the buffers.
	 *  This function can be used as many times as we want in the hashing process.
	 *  Examples on hmac_md5 functions.
	 * 
	 *  @param *ctxBuf the ctx buffer that will be used
	 *  @param *data the actual data that will be used in the hashing process.
	 *  @param size size_t type, indicated the side of the data pointer.
	 */
	static void MD5Update(void *ctxBuf, const void *data, size_t size);
	#if defined(MD5_LINUX)
			/**
			 * used in linux in order to retrieve the time in milliseconds.
			 *
			 * @return returns the milliseconds in a double format.
			 */
			double millis();
	#endif
private:
	#if defined(MD5_LINUX)
			timeval tv;/**< holds the time value on linux */
	#endif
};
extern MD5 hashMD5;
#endif
