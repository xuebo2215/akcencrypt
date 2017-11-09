#include "com_view_akcencrypt_api_AKCEncryptWrapper.h"

jvalue JNU_CallMethodByName(JNIEnv *env, jboolean *hasException, jobject obj,
		const char *name, const char *descriptor, ...) {
	va_list args;
	jclass clazz;
	jmethodID mid;
	jvalue result;
	if ((*env)->EnsureLocalCapacity(env, 2) == JNI_OK) {
		clazz = (*env)->GetObjectClass(env, obj);
		mid = (*env)->GetMethodID(env, clazz, name, descriptor);
		if (mid) {
			const char *p = descriptor;
			/* skip over argument types to find out the
			  return type */
			while (*p != ')')
				p++;
			/* skip ')' */
			p++;
			va_start(args, descriptor);
			switch (*p) {
			case 'V':
				(*env)->CallVoidMethodV(env, obj, mid, args);
				break;
			case '[':
			case 'L':
				result.l = (*env)->CallObjectMethodV(env, obj, mid, args);
				break;
			case 'Z':
				result.z = (*env)->CallBooleanMethodV(env, obj, mid, args);
				break;
			case 'B':
				result.b = (*env)->CallByteMethodV(env, obj, mid, args);
				break;
			case 'C':
				result.c = (*env)->CallCharMethodV(env, obj, mid, args);
				break;
			case 'S':
				result.s = (*env)->CallShortMethodV(env, obj, mid, args);
				break;
			case 'I':
				result.i = (*env)->CallIntMethodV(env, obj, mid, args);
				break;
			case 'J':
				result.j = (*env)->CallLongMethodV(env, obj, mid, args);
				break;
			case 'F':
				result.f = (*env)->CallFloatMethodV(env, obj, mid, args);
				break;
			case 'D':
				result.d = (*env)->CallDoubleMethodV(env, obj, mid, args);
				break;
			default:
				(*env)->FatalError(env, "illegaldescriptor");
			}
			va_end(args);
		}
		(*env)->DeleteLocalRef(env, clazz);
	}
	if (hasException) {
		*hasException = (*env)->ExceptionCheck(env);
	}
	return result;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeGeneratekeyPair(JNIEnv* env, jobject thiz){

	unsigned char *public_key = 0;
	unsigned char *private_key = 0;
	akc_generate_key_pair(&public_key,&private_key);

	unsigned char * buff_publicKeyAndprivateKey = malloc(AKC_PUBLIC_KEY_LEN + AKC_KEY_LEN);
	memcpy(buff_publicKeyAndprivateKey, public_key , AKC_PUBLIC_KEY_LEN);
	memcpy(buff_publicKeyAndprivateKey+AKC_PUBLIC_KEY_LEN, private_key, AKC_KEY_LEN);

	jbyteArray jarray = (*env)->NewByteArray(env, AKC_PUBLIC_KEY_LEN + AKC_KEY_LEN);
	(*env)->SetByteArrayRegion(env, jarray, 0, AKC_PUBLIC_KEY_LEN + AKC_KEY_LEN, (jbyte *)buff_publicKeyAndprivateKey);

	if (public_key) free(public_key);
	if (private_key) free(private_key);
	if (buff_publicKeyAndprivateKey) free(buff_publicKeyAndprivateKey);

	if (jarray == NULL) {
		return NULL;
	}
	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSenderRootKey(JNIEnv* env, jobject thiz,
																   jbyteArray my_idka,
																   jbyteArray my_otpka,
																   jbyteArray their_spkb,
																   jbyteArray their_idkb,
																   jbyteArray their_otpkb){
	const unsigned char *buf_my_idka = (unsigned char*)((*env)->GetByteArrayElements(env, my_idka, NULL));
	const unsigned char *buf_my_otpka = (unsigned char*)((*env)->GetByteArrayElements(env, my_otpka, NULL));
	const unsigned char *buf_their_spkb = (unsigned char*)((*env)->GetByteArrayElements(env, their_spkb, NULL));
	const unsigned char *buf_their_idkb = (unsigned char*)((*env)->GetByteArrayElements(env, their_idkb, NULL));
	const unsigned char *buf_their_otpkb = (unsigned char*)((*env)->GetByteArrayElements(env, their_otpkb, NULL));


    unsigned char *sender_root_key;
    int sender_root_key_len  = akc_sender_root_key(buf_my_idka, buf_my_otpka, buf_their_spkb, buf_their_idkb, buf_their_otpkb, &sender_root_key);

	(*env)->ReleaseByteArrayElements(env, my_idka, (jbyte*)buf_my_idka, 0);
	(*env)->ReleaseByteArrayElements(env, my_otpka, (jbyte*)buf_my_otpka, 0);
	(*env)->ReleaseByteArrayElements(env, their_spkb, (jbyte*)buf_their_spkb, 0);
	(*env)->ReleaseByteArrayElements(env, their_idkb, (jbyte*)buf_their_idkb, 0);
	(*env)->ReleaseByteArrayElements(env, their_otpkb, (jbyte*)buf_their_otpkb, 0);

	jbyteArray jarray = (*env)->NewByteArray(env, sender_root_key_len);
	(*env)->SetByteArrayRegion(env, jarray, 0, sender_root_key_len, (jbyte *)sender_root_key);

	if (sender_root_key) free(sender_root_key);

	if (jarray == NULL) {
		return NULL;
	}

	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeReceiverRootKey(JNIEnv* env, jobject thiz,
																	 jbyteArray their_idkb,
																	 jbyteArray their_otpkb,
																	 jbyteArray my_spka,
																	 jbyteArray my_idka,
																	 jbyteArray my_otpka){

	const unsigned char *buf_their_idkb = (unsigned char*)((*env)->GetByteArrayElements(env, their_idkb, NULL));
	const unsigned char *buf_their_otpkb = (unsigned char*)((*env)->GetByteArrayElements(env, their_otpkb, NULL));
	const unsigned char *buf_my_spka = (unsigned char*)((*env)->GetByteArrayElements(env, my_spka, NULL));
	const unsigned char *buf_my_idka = (unsigned char*)((*env)->GetByteArrayElements(env, my_idka, NULL));
	const unsigned char *buf_my_otpka = (unsigned char*)((*env)->GetByteArrayElements(env, my_otpka, NULL));


	unsigned char *receiver_root_key;
	int receiver_root_key_len  = akc_receiver_root_key(buf_their_idkb,buf_their_otpkb,buf_my_spka,buf_my_idka,buf_my_otpka,&receiver_root_key);

	(*env)->ReleaseByteArrayElements(env, my_idka, (jbyte*)buf_my_idka, 0);
	(*env)->ReleaseByteArrayElements(env, my_otpka, (jbyte*)buf_my_otpka, 0);
	(*env)->ReleaseByteArrayElements(env, my_spka, (jbyte*)buf_my_spka, 0);
	(*env)->ReleaseByteArrayElements(env, their_idkb, (jbyte*)buf_their_idkb, 0);
	(*env)->ReleaseByteArrayElements(env, their_otpkb, (jbyte*)buf_their_otpkb, 0);

	jbyteArray jarray = (*env)->NewByteArray(env, receiver_root_key_len);
	(*env)->SetByteArrayRegion(env, jarray, 0, receiver_root_key_len, (jbyte *)receiver_root_key);

	if (receiver_root_key) free(receiver_root_key);

	if (jarray == NULL) {
		return NULL;
	}

	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeChainKey(JNIEnv* env, jobject thiz,
															  jbyteArray root_chain_key,
															  jint count){

	const unsigned char *buf_root_chain_key = (unsigned char*)((*env)->GetByteArrayElements(env, root_chain_key, NULL));


	unsigned char *chain_key_out;
	int chain_key_out_len  = akc_chain_key(buf_root_chain_key,count,&chain_key_out);

	(*env)->ReleaseByteArrayElements(env, root_chain_key, (jbyte*)buf_root_chain_key, 0);

	jbyteArray jarray = (*env)->NewByteArray(env, chain_key_out_len);
	(*env)->SetByteArrayRegion(env, jarray, 0, chain_key_out_len, (jbyte *)chain_key_out);

	if (chain_key_out) free(chain_key_out);

	if (jarray == NULL) {
		return NULL;
	}
	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeChainKeyNext(JNIEnv* env, jobject thiz,
															  jbyteArray chain_key){

	const unsigned char *buf_chain_key = (unsigned char*)((*env)->GetByteArrayElements(env, chain_key, NULL));


	unsigned char *chain_key_next_out;
	int chain_key_next_out_len  = akc_chain_key_next(buf_chain_key,&chain_key_next_out);

	(*env)->ReleaseByteArrayElements(env, chain_key, (jbyte*)buf_chain_key, 0);

	jbyteArray jarray = (*env)->NewByteArray(env, chain_key_next_out_len);
	(*env)->SetByteArrayRegion(env, jarray, 0, chain_key_next_out_len, (jbyte *)chain_key_next_out);

	if (chain_key_next_out) free(chain_key_next_out);

	if (jarray == NULL) {
		return NULL;
	}
	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeMessageKeyAndIV(JNIEnv* env, jobject thiz,
																	 jbyteArray chain_key,
																	 jbyteArray message_id){
    unsigned long message_idLen  = (*env)->GetArrayLength(env, message_id);
	const unsigned char *buf_chain_key = (unsigned char*)((*env)->GetByteArrayElements(env, chain_key, NULL));
	const unsigned char *buf_message_id = (unsigned char*)((*env)->GetByteArrayElements(env, message_id, NULL));

	unsigned char *messagekey_out;
	unsigned char *miv_out;
	int out_len  = akc_message_keys(buf_chain_key,buf_message_id,message_idLen,&messagekey_out,&miv_out);

	unsigned char * buff_keyandiv = malloc(out_len*2);
	memcpy(buff_keyandiv, messagekey_out , out_len);
	memcpy(buff_keyandiv+out_len, miv_out, out_len);

	(*env)->ReleaseByteArrayElements(env, chain_key, (jbyte*)buf_chain_key, 0);
	(*env)->ReleaseByteArrayElements(env, message_id, (jbyte*)buf_message_id, 0);


	jbyteArray jarray = (*env)->NewByteArray(env, out_len*2);
	(*env)->SetByteArrayRegion(env, jarray, 0, out_len*2, (jbyte *)buff_keyandiv);

	if (messagekey_out) free(messagekey_out);
	if (miv_out) free(miv_out);
	if (buff_keyandiv) free(buff_keyandiv);

	if (jarray == NULL) {
		return NULL;
	}
	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSignature(JNIEnv* env, jobject thiz,
                                                               jbyteArray my_spka,
                                                               jbyteArray datasignature){

    unsigned long datasignature_Len  = (*env)->GetArrayLength(env, datasignature);
    const unsigned char *buf_my_spka = (unsigned char*)((*env)->GetByteArrayElements(env, my_spka, NULL));
    const unsigned char *buf_datasignature = (unsigned char*)((*env)->GetByteArrayElements(env, datasignature, NULL));

    unsigned char *signature;
    int res =  akc_signature(buf_my_spka, buf_datasignature,datasignature_Len,&signature);

    (*env)->ReleaseByteArrayElements(env, my_spka, (jbyte*)buf_my_spka, 0);
    (*env)->ReleaseByteArrayElements(env, datasignature, (jbyte*)buf_datasignature, 0);

    jbyteArray jarray = NULL;
    if (res==1){
        jarray = (*env)->NewByteArray(env, AKC_PUBLIC_KEY_LEN);
        (*env)->SetByteArrayRegion(env, jarray, 0, AKC_PUBLIC_KEY_LEN, (jbyte *)signature);
    }

    if (signature) free(signature);

    if (jarray == NULL) {
        return NULL;
    }

    return jarray;
}

jint
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeVerifySignature(JNIEnv* env, jobject thiz,
                                                                     jbyteArray their_spkb,
                                                                     jbyteArray datasignature,
                                                                     jbyteArray signature){

    unsigned long datasignature_Len  = (*env)->GetArrayLength(env, datasignature);
    const unsigned char *buf_their_spkb = (unsigned char*)((*env)->GetByteArrayElements(env, their_spkb, NULL));
    const unsigned char *buf_datasignature = (unsigned char*)((*env)->GetByteArrayElements(env, datasignature, NULL));
    const unsigned char *buf_signature = (unsigned char*)((*env)->GetByteArrayElements(env, signature, NULL));

    int res = akc_verify_signature(buf_their_spkb,buf_datasignature,datasignature_Len,buf_signature);

    (*env)->ReleaseByteArrayElements(env, their_spkb, (jbyte*)buf_their_spkb, 0);
    (*env)->ReleaseByteArrayElements(env, datasignature, (jbyte*)buf_datasignature, 0);
    (*env)->ReleaseByteArrayElements(env, signature, (jbyte*)buf_signature, 0);

    return res;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeEncryptData(JNIEnv* env, jobject thiz,
																 jbyteArray input,
																 jlong inlen,
																 jbyteArray key,
																 jbyteArray iv){
	unsigned long plainLen  = inlen;
	const unsigned char *buf_plain = (unsigned char*)((*env)->GetByteArrayElements(env, input, NULL));
	const unsigned char *buf_key = (unsigned char*)((*env)->GetByteArrayElements(env, key, NULL));
	const unsigned char *buf_iv = (unsigned char*)((*env)->GetByteArrayElements(env, iv, NULL));

    unsigned char *encrypt_out;
    unsigned long encrypt_out_len =  akc_sm4_encrypt(buf_plain, plainLen,buf_key,buf_iv,&encrypt_out);

	(*env)->ReleaseByteArrayElements(env, input, (jbyte*)buf_plain, 0);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte*)buf_key, 0);
	(*env)->ReleaseByteArrayElements(env, iv, (jbyte*)buf_iv, 0);

	jbyteArray jarray = (*env)->NewByteArray(env, encrypt_out_len);
	(*env)->SetByteArrayRegion(env, jarray, 0, encrypt_out_len, (jbyte *)encrypt_out);

	if (encrypt_out) free(encrypt_out);

	if (jarray == NULL) {
		return NULL;
	}

	return jarray;
}

jbyteArray
Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeDecryptData(JNIEnv* env, jobject thiz,
																 jbyteArray input,
																 jlong inlen,
																 jbyteArray key,
																 jbyteArray iv){
	unsigned long encryptLen  = inlen;
	const unsigned char *buf_encrypt = (unsigned char*)((*env)->GetByteArrayElements(env, input, NULL));
	const unsigned char *buf_key = (unsigned char*)((*env)->GetByteArrayElements(env, key, NULL));
	const unsigned char *buf_iv = (unsigned char*)((*env)->GetByteArrayElements(env, iv, NULL));

    unsigned char *decrypt_out;
    unsigned long decrypt_out_len =  akc_sm4_decrypt(buf_encrypt, encryptLen,buf_key,buf_iv,&decrypt_out);

	(*env)->ReleaseByteArrayElements(env, input, (jbyte*)buf_encrypt, 0);
	(*env)->ReleaseByteArrayElements(env, key, (jbyte*)buf_key, 0);
	(*env)->ReleaseByteArrayElements(env, iv, (jbyte*)buf_iv, 0);

	jbyteArray jarray = (*env)->NewByteArray(env, decrypt_out_len);
	(*env)->SetByteArrayRegion(env, jarray, 0, decrypt_out_len, (jbyte *)decrypt_out);

	if (jarray == NULL) {
		return NULL;
	}

	return jarray;
}
