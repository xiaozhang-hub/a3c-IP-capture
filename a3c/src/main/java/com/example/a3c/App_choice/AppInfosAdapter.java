package com.example.a3c.App_choice;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.example.a3c.R;

import java.util.List;

public class AppInfosAdapter extends BaseAdapter {
    Context context;
    List<AppInfo> appInfos;

    public AppInfosAdapter() {}

    public AppInfosAdapter(Context context , List<AppInfo> infos ){
        this.context = context;
        this.appInfos = infos;
    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public List<AppInfo> getAppInfos() {
        return appInfos;
    }

    public void setAppInfos(List<AppInfo> appInfos) {
        this.appInfos = appInfos;
    }

    @Override
    public int getCount() {
        int count = 0;
        if(null != appInfos){
            return appInfos.size();
        }
        return count;
    }

    @Override
    public Object getItem(int index) {
        return appInfos.get(index);
    }

    @Override
    public long getItemId(int index) {
        return index;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup arg2) {
        ViewHolder viewHolder = null;
        if(null == convertView) {
            viewHolder = new ViewHolder();
            LayoutInflater mInflater = LayoutInflater.from(context);
            convertView = mInflater.inflate(R.layout.appchoose_item, null);
            viewHolder.appIconImg = (ImageView)convertView.findViewById(R.id.appicon);
            viewHolder.appNameText = (TextView)convertView.findViewById(R.id.appname);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder)convertView.getTag();
        }
        if(null != appInfos) {
            viewHolder.appIconImg.setBackground(appInfos.get(position).getIcon());
            viewHolder.appNameText.setText(appInfos.get(position).getAppName());

        }
        return convertView;
    }

    private class ViewHolder {
        ImageView appIconImg;  //图标
        TextView  appNameText;  //应用名称
    }

}
