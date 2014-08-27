package ru.rutoken.demobank;

import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;


public class PaymentsActivity extends Activity {
    private LinearLayout mPaymentsLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_payments);

        setRequestedOrientation(
                ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT);

        setupActionBar();
        setupUI();
    }

    private void setupActionBar() {
        LayoutInflater inflater = (LayoutInflater) this.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View v = inflater.inflate(R.layout.actionbar_layout, null);

        ActionBar.LayoutParams params = new ActionBar.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER);

        /*Custom actionbar*/
        ActionBar actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_CUSTOM);
            actionBar.setDisplayHomeAsUpEnabled(true);
            actionBar.setDisplayShowTitleEnabled(false);
            actionBar.setBackgroundDrawable(
                    this.getResources().getDrawable(R.drawable.ab_bg));
            actionBar.setCustomView(v, params);
        }
    }

    private void setupUI() {
        mPaymentsLayout = (LinearLayout)findViewById(R.id.paymentsLayout);

        int[] paymentsIds = new int[2];
        paymentsIds[0] = R.array.bashneft_payment;
        paymentsIds[1] = R.array.lukoil_payment;
        createPayments(paymentsIds);
    }

    private void createPayments(final int[] IDs) {
        for (int i = 0; i < IDs.length; ++i) {
            PaymentView view = new PaymentView(PaymentsActivity.this);

            String[] data = getResources().getStringArray(IDs[i]);
            view.setNum(getString(R.string.number) + data[0]);
            view.setDate(data[1]);
            view.setReciever(data[2]);
            view.setAmount(data[3]);

            mPaymentsLayout.addView(view);
            view.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    showPaymentInfo();
                }
            });
        }
    }

    private void showPaymentInfo() {
        AlertDialog.Builder builder = new AlertDialog.Builder(PaymentsActivity.this);
        builder.setCancelable(true);

        AlertDialog dialog = builder.create();
        View infoView = (LinearLayout)getLayoutInflater().inflate(R.layout.payment_info_layout, null);
        dialog.setView(infoView);

        final TextView paymentInfoTextView = (TextView)infoView.findViewById(R.id.dataTV);
        final Button sendButton = (Button)infoView.findViewById(R.id.sendB);
        final EditText signEditText = (EditText)infoView.findViewById(R.id.signET);
        final Button signButton = (Button)infoView.findViewById(R.id.signB);

        signButton.setVisibility(View.GONE);
        signEditText.setVisibility(View.GONE);

        sendButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                paymentInfoTextView.setVisibility(View.GONE);
                sendButton.setVisibility(View.GONE);

                signButton.setVisibility(View.VISIBLE);
                signEditText.setVisibility(View.VISIBLE);
            }
        });

        signButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                signButton.setVisibility(View.GONE);
                signEditText.setVisibility(View.GONE);
            }
        });

        dialog.show();
    }
}