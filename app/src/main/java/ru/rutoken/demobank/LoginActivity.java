/*
 * Copyright (c) 2018, JSC Aktiv-Soft. See https://download.rutoken.ru/License_Agreement.pdf
 * All Rights Reserved.
 */

package ru.rutoken.demobank;

import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.res.Configuration;
import android.graphics.Color;
import android.os.Bundle;
import androidx.appcompat.app.ActionBar;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.DisplayMetrics;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11caller.Token;
import ru.rutoken.pkcs11caller.TokenManager;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.utils.Pkcs11ErrorTranslator;

public class LoginActivity extends Pkcs11CallerActivity {
    // GUI
    private Button mLoginButton;
    private EditText mPinEditText;
    private TextView mAlertTextView;
    private ProgressBar mLoginProgressBar;

    protected NativeLong mSlotId = TokenManagerListener.NO_SLOT;
    protected NativeLong mCertificate = TokenManagerListener.NO_CERTIFICATE;
    protected Token mToken = null;

    private static final byte mSignData[] = new byte[] {0, 0, 0};
    private Dialog mOverlayDialog;

    public String getActivityClassIdentifier() {
        return getClass().getName();
    }

    protected void showLogonStarted() {
        mLoginProgressBar.setVisibility(View.VISIBLE);
        mLoginButton.setEnabled(false);
        mOverlayDialog.show();
    }

    protected void showLogonFinished() {
        mLoginProgressBar.setVisibility(View.GONE);
        mLoginButton.setEnabled(true);
        mOverlayDialog.dismiss();
    }

    @Override
    protected void manageLoginError(Pkcs11Exception exception) {
        if (exception != null) {
            mAlertTextView.setText(Pkcs11ErrorTranslator.getInstance(this).messageForRV(exception.getErrorCode()));
        }
        showLogonFinished();
    }

    @Override
    protected void manageLoginSucceed() {
        sign(mToken, mCertificate, mSignData);
    }

    @Override
    protected void manageSignError(Pkcs11Exception exception) {
        logout(mToken);
    }

    @Override
    protected void manageSignSucceed(byte[] data) {
        showLogonFinished();
        Intent intent = new Intent(LoginActivity.this, PaymentsActivity.class);
        intent.putExtra("slotId", mSlotId);
        intent.putExtra("certificate", mCertificate);
        startActivity(intent);
    }

    @Override
    protected void manageLogoutError(Pkcs11Exception exception) {
        showLogonFinished();
    }

    @Override
    protected void manageLogoutSucceed() {
        showLogonFinished();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        DisplayMetrics displayMetrics = getResources().getDisplayMetrics();
        if ((displayMetrics.density > 1.0) && ((getResources().getConfiguration().screenLayout &
                Configuration.SCREENLAYOUT_SIZE_MASK) ==
                Configuration.SCREENLAYOUT_SIZE_XLARGE)) {
            setContentView(R.layout.activity_login_high_density);
        } else {
            setContentView(R.layout.activity_login);
        }

        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT);

        setupActionBar();
        setupUI();

        Intent intent = getIntent();
        mSlotId = (NativeLong) intent.getSerializableExtra("slotId");
        mCertificate = (NativeLong) intent.getSerializableExtra("certificate");
        mToken = TokenManager.getInstance().tokenForSlot(mSlotId);
        if (null == mToken) {
            finish();
        }
        mOverlayDialog = new Dialog(this, android.R.style.Theme_Panel);
        mOverlayDialog.setCancelable(false);
    }

    private void setupActionBar() {
        LayoutInflater inflater = (LayoutInflater) this.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View v = inflater.inflate(R.layout.actionbar_layout, null);

        ActionBar.LayoutParams params = new ActionBar.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER);

        /* Custom actionbar */
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_CUSTOM);
            actionBar.setDisplayHomeAsUpEnabled(false);
            actionBar.setDisplayShowTitleEnabled(false);
            actionBar.setBackgroundDrawable(getDrawable(R.drawable.ab_bg));
            actionBar.setCustomView(v, params);
        }
    }

    private void setupUI() {
        mLoginButton = findViewById(R.id.loginB);
        mPinEditText = findViewById(R.id.pinET);
        mAlertTextView = findViewById(R.id.alertTV);
        mLoginProgressBar = findViewById(R.id.loginPB);

        mLoginProgressBar.setVisibility(View.GONE);

        mLoginButton.setBackgroundColor(Color.TRANSPARENT);
        mLoginButton.setEnabled(false);

        mPinEditText.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
                if (mPinEditText.getText().toString().isEmpty()) {
                    mLoginButton.setEnabled(false);
                }
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {

            }

            @Override
            public void afterTextChanged(Editable editable) {
                if (mPinEditText.getText().toString().isEmpty()) {
                    mLoginButton.setEnabled(false);
                } else {
                    mLoginButton.setEnabled(true);
                }
            }
        });

        mLoginButton.setOnClickListener(view -> {
            TokenManagerListener.getInstance().resetWaitForToken();
            showLogonStarted();
            login(mToken, mPinEditText.getText().toString());

        });
    }
}
