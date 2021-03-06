/*
 * Copyright (c) 2018, JSC Aktiv-Soft. See https://download.rutoken.ru/License_Agreement.pdf
 * All Rights Reserved.
 */

package ru.rutoken.demobank;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.text.Html;
import android.text.Spanned;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.widget.Toast;

import com.sun.jna.NativeLong;

import java.text.DateFormat;
import java.util.Date;
import java.util.Objects;

import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AlertDialog;
import ru.rutoken.pkcs11caller.Token;
import ru.rutoken.pkcs11caller.TokenManager;
import ru.rutoken.pkcs11caller.exception.Pkcs11Exception;
import ru.rutoken.utils.Pkcs11ErrorTranslator;
import ru.rutoken.utils.TokenBatteryCharge;
import ru.rutoken.utils.TokenModelRecognizer;

public class PaymentsActivity extends Pkcs11CallerActivity {
    private class InfoDialog {
        final AlertDialog mDialog;
        final Button mConfirmButton;
        final TextView mPaymentTextView;

        InfoDialog() {
            AlertDialog.Builder builder = new AlertDialog.Builder(PaymentsActivity.this);
            builder.setCancelable(true);
            mDialog = builder.create();
            View view = getLayoutInflater().inflate(R.layout.payment_info_layout, null);
            mDialog.setView(view);
            mConfirmButton = view.findViewById(R.id.sendB);
            mPaymentTextView = view.findViewById(R.id.dataTV);
        }

        void show(Spanned text, boolean bNeedAskPIN) {
            mPaymentTextView.setText(text);

            if (bNeedAskPIN) {
                mConfirmButton.setOnClickListener(view -> {
                    mDialog.dismiss();
                    mLoginDialog.show(null);
                });
            } else {
                mConfirmButton.setOnClickListener(view -> {
                    mDialog.dismiss();
                    signAction();
                });
            }
            mDialog.show();
        }
    }

    private class LoginDialog {
        final AlertDialog mDialog;
        final EditText mPinEditText;
        final TextView mErrorTextView;
        String mPin;
        boolean mLogonBeingPerformed = false;

        LoginDialog() {
            AlertDialog.Builder builder = new AlertDialog.Builder(PaymentsActivity.this);
            builder.setCancelable(true);

            mDialog = builder.create();
            View view = getLayoutInflater().inflate(R.layout.login_dialog, null);
            Button loginButton = view.findViewById(R.id.signB);
            mPinEditText = view.findViewById(R.id.signET);
            mErrorTextView = view.findViewById(R.id.errorTV);
            mDialog.setView(view);
            loginButton.setOnClickListener(view1 -> {
                mPin = mPinEditText.getText().toString();
                mPinEditText.setText("");
                mDialog.dismiss();
                mLogonBeingPerformed = true;
                startLoginAndSignAction();
            });
        }

        String pin() {
            return mPin;
        }

        void show(String errorText) {
            if (mLogonBeingPerformed) {
                mDialog.setOnCancelListener(dialogInterface -> {
                    mLogonBeingPerformed = false;
                    onBackPressed();
                });
            } else {
                mDialog.setOnCancelListener(dialogInterface -> mDialog.cancel());
            }
            if (null != errorText) {
                mErrorTextView.setText(errorText);
            } else {
                mErrorTextView.setText("");
            }
            Objects.requireNonNull(mDialog.getWindow()).setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
            mDialog.show();

        }

        boolean isLogonBeingPerformed() {
            return mLogonBeingPerformed;
        }

        void setLogonFinished() {
            mLogonBeingPerformed = false;
        }
    }

    // GUI
    private LinearLayout mPaymentsLayout;
    private TextView mTokenModelTextView;
    private TextView mTokenIDTextView;
    private TextView mTokenBatteryTextView;
    private ImageView mTokenBatteryImageView;
    private PopupWindow mPopupWindow;
    private InfoDialog mInfoDialog;
    private LoginDialog mLoginDialog;
    private AlertDialog mSucceedDialog;
    private AlertDialog mProgressDialog;

    private String[] mPaymentTitles;
    private String[][] mPaymentArray = null;
    //

    private static final byte[] mSignData = new byte[]{
            0, 0, 0
    };

    // Activity input
    protected NativeLong mSlotId = TokenManagerListener.NO_SLOT;
    protected NativeLong mCertificate = TokenManagerListener.NO_CERTIFICATE;
    protected Token mToken = null;
    //

    // Logic
    private int mChecksCount = 0;
    //

    public String getActivityClassIdentifier() {
        return getClass().getName();
    }

    //

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_payments);

        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT);

        setupActionBar();
        Intent intent = getIntent();
        mSlotId = (NativeLong) intent.getSerializableExtra("slotId");
        mCertificate = (NativeLong) intent.getSerializableExtra("certificate");
        mToken = TokenManager.getInstance().tokenForSlot(mSlotId);
        if (null == mToken) {
            finish();
        }
        TokenManagerListener.getInstance().setPaymentsCreated();
        setupUI();
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
        mPaymentsLayout = findViewById(R.id.paymentsLayout);
        mTokenBatteryTextView = findViewById(R.id.percentageTV);
        mTokenIDTextView = findViewById(R.id.tokenIdTV);
        mTokenModelTextView = findViewById(R.id.modelTV);
        mTokenBatteryImageView = findViewById(R.id.batteryIV);

        mTokenModelTextView.setText(TokenModelRecognizer.getInstance(this).marketingNameForPkcs11Name(mToken.getModel())
                + " " + mToken.getShortDecSerialNumber());
        mTokenIDTextView.setText("");

        if (mToken.getModel().contains("ECP BT")) {
            int charge = TokenBatteryCharge.getBatteryPercentage(mToken.getCharge());
            mTokenBatteryTextView.setText(charge + "%");
            mTokenBatteryImageView.setImageResource(TokenBatteryCharge.getBatteryImageForVoltage(mToken.getCharge()));
        } else {
            mTokenBatteryTextView.setText("");
            mTokenBatteryImageView.setImageResource(android.R.color.transparent);
        }

        LayoutInflater inflater = (LayoutInflater) getBaseContext().getSystemService(LAYOUT_INFLATER_SERVICE);
        View popupView = inflater.inflate(R.layout.popup_layout, null);
        mPopupWindow = new PopupWindow(popupView, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);

        Button popupButton = popupView.findViewById(R.id.popupB);
        popupButton.setOnClickListener(view -> {
            boolean bNeedAskPIN = false;
            int paymentsCount = 0;
            for (int i = 0; i < mPaymentsLayout.getChildCount(); ++i) {
                View childView = mPaymentsLayout.getChildAt(i);
                if (Payment.class.isInstance(childView)) {
                    Payment payment = (Payment) childView;
                    CheckBox checkBox = payment.findViewById(R.id.checkBox);
                    if (checkBox.isChecked()) {
                        bNeedAskPIN = bNeedAskPIN || payment.needAskPIN();
                        ++paymentsCount;
                    }
                }
            }
            showBatchPaymentInfo(paymentsCount, bNeedAskPIN);
        });

        createSucceedDialog();
        mInfoDialog = new InfoDialog();
        mLoginDialog = new LoginDialog();
        createProgressDialog();

        createPayments();
    }

    protected void uncheckAllPayments() {
        for (int i = 0; i < mPaymentsLayout.getChildCount(); ++i) {
            View childView = mPaymentsLayout.getChildAt(i);
            if (Payment.class.isInstance(childView)) {
                Payment payment = (Payment) childView;
                CheckBox checkBox = payment.findViewById(R.id.checkBox);
                checkBox.setChecked(false);
            }
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                onBackPressed();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onBackPressed() {
        TokenManagerListener.getInstance().resetPaymentsCreated();
        logout(mToken);
        super.onBackPressed();
    }

    @Override
    protected void manageLoginError(Pkcs11Exception exception) {
        mProgressDialog.dismiss();
        String message = null;
        if (exception != null) {
            message = Pkcs11ErrorTranslator.getInstance(this).messageForRV(exception.getErrorCode());
        }
        mLoginDialog.show(message);
    }

    @Override
    protected void manageLoginSucceed() {
        mLoginDialog.setLogonFinished();
        sign(mToken, mCertificate, mSignData);
    }

    @Override
    protected void manageSignError(Pkcs11Exception exception) {
        uncheckAllPayments();
        mProgressDialog.dismiss();
        String message = getString(R.string.error);
        if (exception != null) {
            message = Pkcs11ErrorTranslator.getInstance(this).messageForRV(exception.getErrorCode());
        }
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void manageSignSucceed(byte[] data) {
        uncheckAllPayments();
        mProgressDialog.dismiss();
        mSucceedDialog.show();
    }

    @Override
    protected void manageLogoutError(Pkcs11Exception exception) {
        if (mLoginDialog.isLogonBeingPerformed()) {
            login(mToken, mLoginDialog.pin());
        }
    }

    @Override
    protected void manageLogoutSucceed() {
        if (mLoginDialog.isLogonBeingPerformed()) {
            login(mToken, mLoginDialog.pin());
        }
    }

    private void createPayments() {
        Resources res = getResources();
        mPaymentTitles = res.getStringArray(R.array.payments_titles);
        TypedArray ta = res.obtainTypedArray(R.array.payments);
        int n = ta.length();
        mPaymentArray = new String[n][];
        for (int i = 0; i < n; ++i) {
            int id = ta.getResourceId(i, 0);
            if (id > 0) {
                mPaymentArray[i] = res.getStringArray(id);
            } else {
                // something wrong with the XML
            }
        }
        ta.recycle();

        int nRecipient = 0;
        int nPrice = 0;
        for (int i = 0; i < mPaymentTitles.length; ++i) {
            if (mPaymentTitles[i].equals(res.getString(R.string.recipient))) {
                nRecipient = i;
            }
            if (mPaymentTitles[i].equals(res.getString(R.string.price))) {
                nPrice = i;
            }
        }

        for (int i = 0; i < mPaymentArray.length; ++i) {
            int price = Integer.valueOf(mPaymentArray[i][nPrice]);
            Payment payment = new Payment(this, null, i, mPaymentArray[i][nRecipient], price);
            payment.setOnClickListener(view -> {
                if (!Payment.class.isInstance(view)) return;
                showOnePaymentInfo((Payment) view);
            });
            CheckBox checkBox = payment.findViewById(R.id.checkBox);
            checkBox.setOnCheckedChangeListener((compoundButton, b) -> {
                if (b) {
                    ++mChecksCount;
                    mPopupWindow.showAtLocation(mPaymentsLayout, Gravity.BOTTOM, 0, 0);
                } else {
                    --mChecksCount;
                    if (mChecksCount == 0) {
                        mPopupWindow.dismiss();
                    }
                }
            });
            mPaymentsLayout.addView(payment);
        }
    }

    protected void startLoginAndSignAction() {
        mProgressDialog.show();
        logout(mToken);
    }

    protected void signAction() {
        mProgressDialog.show();
        sign(mToken, mCertificate, mSignData);
    }

    protected String createFullPaymentHtml(int num) {
        StringBuilder result = new StringBuilder();
        DateFormat df = DateFormat.getDateInstance();
        String date = df.format(new Date());
        result.append("<h3>").append(getString(R.string.payment)).append(String.format("%d", num + Payment.FIRST_NUMBER)).append("</h3>");
        result.append("<font color=#CCCCCC>").append(getString(R.string.fromDate)).append(" ").append(date).append("</font>");
        result.append("<br/><br/>");
        for (int i = 0; i < mPaymentTitles.length; ++i) {
            result.append("<font color=#CCCCCC size=-1>").append(mPaymentTitles[i]).append("</font><br/>");
            result.append("<font color=#000000 size=-1>").append(mPaymentArray[num][i]).append("</font><br/>");
        }
        return result.toString();
    }

    private void showBatchPaymentInfo(int count, boolean bNeedAskPIN) {
        String message = String.format(getString(R.string.batch_sign_message), count);
        if (bNeedAskPIN) {
            message += "<br />" + getString(R.string.need_pin_message);
        } else {
            message += "<br />" + getString(R.string.batch_require_proceed);
        }
        mInfoDialog.show(Html.fromHtml(message), bNeedAskPIN);
    }

    private void showOnePaymentInfo(Payment payment) {
        if (null == payment) return;
        int number = payment.getNum();

        mInfoDialog.show(Html.fromHtml(createFullPaymentHtml(number)), payment.needAskPIN());
    }

    private void createProgressDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(PaymentsActivity.this);
        builder.setCancelable(false);
        mProgressDialog = builder.create();
        View view = getLayoutInflater().inflate(R.layout.progress_dialog, null);
        mProgressDialog.setView(view);
    }

    private void createSucceedDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(PaymentsActivity.this);
        builder.setCancelable(true);
        mSucceedDialog = builder.create();
        View successView = getLayoutInflater().inflate(R.layout.result_dialog_layout, null);
        successView.setOnClickListener(view -> mSucceedDialog.dismiss());
        mSucceedDialog.setView(successView);
    }
}
