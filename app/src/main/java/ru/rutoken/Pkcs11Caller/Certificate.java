package ru.rutoken.Pkcs11Caller;

import android.os.Parcel;
import android.os.Parcelable;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.IntByReference;

import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import ru.rutoken.Pkcs11.CK_ATTRIBUTE;
import ru.rutoken.Pkcs11.Pkcs11Constants;

/**
 * Created by mironenko on 20.08.2014.
 */
public class Certificate extends Pkcs11Parcelable {
    String mId;
    String mSubject;

    Certificate(Parcel parcel) {
        mId = parcel.readString();
        mSubject = parcel.readString();
    }

    Certificate(int hSession, int hObject) throws Pkcs11Exception {
        int rv;
        final int ulMaxObjectsCount = 100;
        IntByReference ulObjectCount = new IntByReference(ulMaxObjectsCount);
        int[] hObjects = null;
        int[] hTmpObjects = new int[ulMaxObjectsCount];
        CK_ATTRIBUTE[] certAttributes = new CK_ATTRIBUTE[2];

        certAttributes[0].type = Pkcs11Constants.CKA_ID;
        certAttributes[0].pValue = null;
        certAttributes[0].ulValueLen = 0;

        certAttributes[1].type = Pkcs11Constants.CKA_SUBJECT;
        certAttributes[1].pValue = null;
        certAttributes[1].ulValueLen = 0;

        rv = RtPkcs11Library.getInstance().C_GetAttributeValue(hSession, hObject, certAttributes, certAttributes.length);
        if (Pkcs11Constants.CKR_OK != rv) {
            throw Pkcs11Exception.exceptionWithCode(rv);
        }
        for (int i = 0; i < certAttributes.length; ++i)
            certAttributes[i].pValue = new Memory(certAttributes[i].ulValueLen);
        rv = RtPkcs11Library.getInstance().C_GetAttributeValue(hSession, hObject, certAttributes, certAttributes.length);
        if (Pkcs11Constants.CKR_OK != rv) {
            throw Pkcs11Exception.exceptionWithCode(rv);
        }
        byte id[] = certAttributes[0].pValue.getByteArray(0, certAttributes[0].ulValueLen);
        byte subjectDER[] = certAttributes[1].pValue.getByteArray(0, certAttributes[1].ulValueLen);

        mId = new String();
        for (int i = 0; i < id.length; ++i) {
            String chr = String.format("%02x", id[i]);
            mId += chr;
        }
        X500Principal principal = new X500Principal(subjectDER);
        mSubject = principal.getName();
    }

    public String id() { return mId; }
    public String subject() { return mSubject; }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(mId);
        parcel.writeString(mSubject);
    }
}
