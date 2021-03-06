/*
 * Copyright (c) 2018, JSC Aktiv-Soft. See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package ru.rutoken.pkcs11caller;

import android.os.AsyncTask;

import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;

abstract class Pkcs11AsyncTask extends AsyncTask<Void, Void, Pkcs11Result> {
    final RtPkcs11 mPkcs11 = RtPkcs11Library.getInstance();
    final Pkcs11Callback mCallback;

    protected abstract Pkcs11Result doWork() throws Pkcs11CallerException;

    Pkcs11AsyncTask(Pkcs11Callback callback) {
        mCallback = callback;
    }

    @Override
    protected Pkcs11Result doInBackground(Void... voids) {
        try {
            synchronized (mPkcs11) {
                return doWork();
            }
        } catch (Pkcs11CallerException exception) {
            return new Pkcs11Result(exception);
        }
    }

    @Override
    protected void onPostExecute(Pkcs11Result result) {
        if (result == null) mCallback.execute();
        else if (result.exception == null) mCallback.execute(result.arguments);
        else mCallback.execute(result.exception);
    }
}
