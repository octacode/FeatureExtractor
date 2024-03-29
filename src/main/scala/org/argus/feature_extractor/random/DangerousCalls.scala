package org.argus.feature_extractor

import scala.collection.mutable

package object DangerousCalls {
  val hashMap: mutable.LinkedHashMap[String, Integer] = mutable.LinkedHashMap(
    ("Landroid/os/SystemClock;->elapsedRealtime()J", 0),
    ("Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V", 0),
    ("Landroid/webkit/WebChromeClient$CustomViewCallback;", 0),
    ("Landroid/app/Notification;-><init>()V", 0),
    ("Ldalvik/system/DexClassLoader", 0),
    ("Landroid/os/Handler;->obtainMessage:()Landroid/os/Message;", 0),
    ("Landroid/os/Handler;->sendMessage:(Landroid/os/Message;)Z", 0),
    ("Landroid/app/Notification;->icon:I", 0),
    ("Landroid/widget/ImageButton;->setBackgroundColor(I)V", 0),
    ("Landroid/widget/RelativeLayout;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V", 0),
    ("Landroid/net/Uri$Builder;->appendPath(Ljava/lang/String;)Landroid/net/Uri$Builder;", 0),
    ("Landroid/graphics/drawable/GradientDrawable;", 0),
    ("Landroid/content/pm/PackageManager;->getPackageArchiveInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", 0),
    ("Landroid/view/animation/ScaleAnimation;->setDuration(J)V", 0),
    ("Landroid/view/MotionEvent;->obtain(JJIFFFFIFFII)Landroid/view/MotionEvent;", 0),
    ("Landroid/os/Parcel;->readList(Ljava/util/List;Ljava/lang/ClassLoader;)V", 0),
    ("Landroid/os/Handler;->obtainMessage()Landroid/os/Message;", 0),
    ("Landroid/webkit/WebResourceResponse;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/io/InputStream;)V", 0),
    ("Landroid/view/animation/Animation;->initialize(IIII)V", 0),
    ("Landroid/app/ActivityManager$RunningTaskInfo;->topActivity:Landroid/content/ComponentName;", 0),
    ("Landroid/webkit/JsResult;->cancel()V", 0),
    ("Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V", 0),
    ("Landroid/app/AlarmManager;->set(IJLandroid/app/PendingIntent;)V", 0),
    ("Landroid/util/AttributeSet;->getAttributeIntValue(Ljava/lang/String;Ljava/lang/String;I)I", 0),
    ("Landroid/widget/MediaController;", 0),
    ("Landroid/os/Message;-><init>()V", 0),
    ("Landroid/webkit/ConsoleMessage;", 0),
    ("Landroid/content/pm/ApplicationInfo;->enabled:Z", 0),
    ("Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V", 0),
    ("Landroid/view/MotionEvent;->recycle()V", 0),
    ("Landroid/telephony/TelephonyManager;->getNetworkOperatorName()Ljava/lang/String;", 0),
    ("Landroid/app/AlertDialog$Builder;->setOnCancelListener(Landroid/content/DialogInterface$OnCancelListener;)Landroid/app/AlertDialog$Builder;", 0),
    ("Landroid/telephony/gsm/GsmCellLocation;", 0),
    ("Landroid/app/AlarmManager;->setRepeating(IJJLandroid/app/PendingIntent;)V", 0),
    ("Landroid/graphics/Camera;->save()V", 0),
    ("Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;", 0),
    ("Landroid/webkit/ConsoleMessage$MessageLevel;->TIP:Landroid/webkit/ConsoleMessage$MessageLevel;", 0),
    ("Landroid/graphics/drawable/GradientDrawable$Orientation;->TOP_BOTTOM:Landroid/graphics/drawable/GradientDrawable$Orientation;", 0),
    ("Landroid/widget/Gallery$LayoutParams;-><init>(II)V", 0),
    ("Landroid/content/Context;->bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z", 0),
    ("Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V", 0),
    ("Landroid/net/Uri;->getScheme()Ljava/lang/String;", 0),
    ("Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;", 0),
    ("Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;", 0),
    ("Landroid/widget/TextView;->setLineSpacing(FF)V", 0),
    ("Landroid/webkit/WebView;->setDownloadListener(Landroid/webkit/DownloadListener;)V", 0),
    ("Landroid/widget/ProgressBar;-><init>(Landroid/content/Context;)V", 0),
    ("Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0", 0),
    ("Landroid/widget/ImageView;->setId(I)V", 0),
    ("Landroid/webkit/WebChromeClient;->onJsAlert(Landroid/webkit/WebView;Ljava/lang/String;Ljava/lang/String;Landroid/webkit/JsResult;)Z", 0),
    ("Landroid/provider/Browser;->BOOKMARKS_URI:Landroid/net/Uri;", 0),
    ("Landroid/app/NotificationManager;->cancel(I)V", 0),
    ("Landroid/content/Context;->getFilesDir()Ljava/io/File;", 0),
    ("Landroid/webkit/WebChromeClient;->onRequestFocus(Landroid/webkit/WebView;)V", 0),
    ("Landroid/view/animation/AlphaAnimation;->startNow()V", 0),
    ("Landroid/os/Parcel;->createStringArray()", 0),
    ("a/a;", 0),
    ("Landroid/os/Parcel;->writeNoException()V", 0),
    ("Landroid/database/CursorWindow;->getInt(II)I", 0),
    ("Landroid/app/ActivityManager;->getRunningTasks(I)Ljava/util/List;", 0),
    ("Landroid/support/v4/app/Fragment;->onDestroy()V", 0),
    ("Landroid/content/Context;->unbindService(Landroid/content/ServiceConnection;)V", 0),
    ("Landroid/graphics/Color;->rgb(III)I", 0),
    ("Landroid/content/res/Resources;->getValue(Ljava/lang/String;Landroid/util/TypedValue;Z)V", 0),
    ("Landroid/widget/MediaController;-><init>(Landroid/content/Context;)V", 0),
    ("Landroid/annotation/SuppressLint;", 0),
    ("Landroid/webkit/JsPromptResult;->confirm(Ljava/lang/String;)V", 0),
    ("Landroid/content/res/TypedArray;->recycle()V", 0),
    ("Landroid/content/pm/ActivityInfo;->configChanges:I", 0),
    ("Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;", 0),
    ("Landroid/app/Activity;->getIntent()Landroid/content/Intent;", 0),
    ("Landroid/telephony/TelephonyManager;->getSimOperator()Ljava/lang/String;", 0),
    ("Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;", 0),
    ("Landroid/widget/RelativeLayout;->onKeyDown(ILandroid/view/KeyEvent;)Z", 0),
    ("Landroid/webkit/WebView;->clearCache(Z)V", 0),
    ("Landroid/webkit/WebSettings;->setDisplayZoomControls(Z)V", 0),
    ("Landroid/support/v4/app/Fragment;->onCreate(Landroid/os/Bundle;)V", 0),
    ("Landroid/os/Parcel;->readDouble()D", 0),
    ("Landroid/app/Activity;->onKeyDown(ILandroid/view/KeyEvent;)Z", 0),
    ("Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;", 0),
    ("Landroid/webkit/ConsoleMessage$MessageLevel;->WARNING:Landroid/webkit/ConsoleMessage$MessageLevel;", 0),
    ("Landroid/view/ViewGroup;->removeAllViews()V", 0),
    ("Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V", 0),
    ("Landroid/telephony/TelephonyManager;->getCellLocation()Landroid/telephony/CellLocation;", 0),
    ("Landroid/webkit/WebSettings;->setDatabasePath(Ljava/lang/String;)V", 0),
    ("Landroid/view/animation/ScaleAnimation;-><init>(FFFFFF)V", 0),
    ("Landroid/app/Notification;->setLatestEventInfo(Landroid/content/Context;Ljava/lang/CharSequence;Ljava/lang/CharSequence;Landroid/app/PendingIntent;)V", 0),
    ("Landroid/net/Proxy;->getDefaultHost()Ljava/lang/String;", 0),
    ("Landroid/net/NetworkInfo;->getExtraInfo()Ljava/lang/String;", 0),
    ("Landroid/webkit/WebChromeClient;->onConsoleMessage(Landroid/webkit/ConsoleMessage;)Z", 0),
    ("Landroid/os/IInterface;", 0),
    ("Landroid/view/animation/TranslateAnimation;-><init>(IFIFIFIF)V", 0),
    ("Landroid/support/v4/app/FragmentActivity;", 0),
    ("Ljava/lang/Runtime;->exec", 0),
    ("Landroid/net/NetworkInfo$State;->CONNECTED:Landroid/net/NetworkInfo$State;", 0),
    ("Landroid/webkit/ConsoleMessage;->messageLevel()Landroid/webkit/ConsoleMessage$MessageLevel;", 0),
    ("Landroid/telephony/TelephonyManager;", 0),
    ("Landroid/widget/VideoView;->setOnCompletionListener(Landroid/media/MediaPlayer$OnCompletionListener;)V", 0),
    ("Landroid/webkit/WebView;->enablePlatformNotifications()V", 0),
    ("Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;", 0),
    ("application/vnd.android.package-archive", 0),
    ("Landroid/webkit/ConsoleMessage;->sourceId()Ljava/lang/String;", 0),
    ("Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;", 0),
    ("Landroid/os/ParcelFileDescriptor;->getFileDescriptor()Ljava/io/FileDescriptor;", 0),
    ("Landroid/widget/VideoView;->seekTo(I)V", 0),
    ("Landroid/graphics/Camera;->rotateY(F)V", 0),
    ("Landroid/app/Notification;->defaults:I", 0),
    ("Landroid/widget/RemoteViews;->setProgressBar(IIIZ)V", 0),
    ("Landroid/os/Parcel;->createFloatArray()", 0),
    ("Landroid/view/animation/AnimationSet;-><init>(Z)V", 0),
    ("Landroid/os/ResultReceiver;", 0),
    ("Landroid/net/NetworkInfo;->isAvailable()Z", 0),
    ("Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V", 0),
    ("Landroid/net/Uri;->buildUpon()Landroid/net/Uri$Builder;", 0),
    ("Landroid/graphics/Point;", 0),
    ("Landroid/webkit/ConsoleMessage$MessageLevel;->ordinal()I", 0),
    ("Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;", 0),
    ("Landroid/view/View$MeasureSpec;->getMode(I)I", 0),
    ("Landroid/telephony/TelephonyManager;->getSimOperatorName()Ljava/lang/String;", 0),
    ("Landroid/app/Service;->onCreate()V", 0),
    ("Landroid/os/Bundle;->keySet()Ljava/util/Set;", 0),
    ("Landroid/webkit/ConsoleMessage;->lineNumber()I", 0),
    ("Landroid/graphics/Bitmap;->getRowBytes()I", 0),
    ("Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V", 0),
    ("Landroid/widget/VideoView;->setMediaController(Landroid/widget/MediaController;)V", 0),
    ("Landroid/net/NetworkInfo;->getTypeName()Ljava/lang/String;", 0),
    ("Landroid/app/Notification;->ledOnMS:I", 0),
    ("Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0", 0),
    ("Landroid/webkit/WebSettings;->setSavePassword(Z)V", 0),
    ("Landroid/graphics/Camera;->translate(FFF)V", 0),
    ("Landroid/support/v4/app/Fragment;->setArguments(Landroid/os/Bundle;)V", 0),
    ("Landroid/app/AlertDialog$Builder;->setNegativeButton(ILandroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;", 0),
    ("Landroid/database/CursorWindow;->CREATOR:Landroid/os/Parcelable$Creator;", 0),
    ("Landroid/widget/VideoView;->setOnPreparedListener(Landroid/media/MediaPlayer$OnPreparedListener;)V", 0),
    ("Landroid/app/Activity;->getComponentName()Landroid/content/ComponentName;", 0),
    ("Landroid/net/wifi/WifiInfo;->getMacAddress()Ljava/lang/String;", 0),
    ("Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;", 0),
    ("Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I", 0),
    ("Landroid/graphics/Point;->y:I", 0),
    ("Landroid/view/MotionEvent;->obtain(Landroid/view/MotionEvent;)Landroid/view/MotionEvent;", 0),
    ("Landroid/support/v4/app/Fragment;", 0),
    ("Landroid/database/CursorWindow;->isNull(II)Z", 0),
    ("Landroid/webkit/WebChromeClient$CustomViewCallback;->onCustomViewHidden()V", 0),
    ("Landroid/widget/RelativeLayout;->getVisibility()I", 0),
    ("Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z", 0),
    ("Landroid/app/Notification;->ledOffMS:I", 0),
    ("Landroid/app/Notification;->ledARGB:I", 0),
    ("Landroid/telephony/gsm/GsmCellLocation;->getCid()I", 0),
    ("Landroid/webkit/WebSettings;->setMediaPlaybackRequiresUserGesture(Z)V", 0),
    ("Landroid/widget/RemoteViews;->setImageViewResource(II)V", 0),
    ("Landroid/webkit/WebView;->setScrollBarStyle(I)V", 0),
    ("Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V", 0),
    ("Landroid/widget/TextView;->setTextSize(F)V", 0),
    ("Landroid/app/Notification;->when:J", 0),
    ("Landroid/telephony/gsm/GsmCellLocation;->getLac()I", 0),
    ("Landroid/view/animation/AnimationSet;", 0),
    ("Landroid/webkit/WebSettings;->setCacheMode(I)V", 0),
    ("Landroid/widget/ViewFlipper;-><init>(Landroid/content/Context;)V", 0),
    ("Landroid/os/Parcel;->recycle()V", 0),
    ("Landroid/view/animation/AccelerateInterpolator;-><init>()V", 0),
    ("Landroid/app/ActivityManager;->getRunningServices(I)Ljava/util/List;", 0),
    ("Landroid/net/wifi/WifiManager;", 0),
    ("Landroid/net/ConnectivityManager;->getNetworkInfo(I)Landroid/net/NetworkInfo;", 0),
    ("Landroid/content/res/TypedArray;->getBoolean(IZ)Z", 0),
    ("Landroid/media/MediaPlayer$OnErrorListener;", 0),
    ("Landroid/net/Uri$Builder;", 0),
    ("Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;", 0),
    ("Landroid/widget/MediaController;->hide()V", 0),
    ("Landroid/widget/VideoView;->pause()V", 0),
    ("Landroid/app/Service;", 0),
    ("Landroid/widget/RemoteViews;", 0),
    ("Landroid/widget/VideoView;->setVideoPath(Ljava/lang/String;)V", 0),
    ("Ljavax/crypto", 0),
    ("Landroid/webkit/WebChromeClient;->onReceivedTitle(Landroid/webkit/WebView;Ljava/lang/String;)V", 0),
    ("Landroid/telephony/cdma/CdmaCellLocation;", 0),
    ("Landroid/location/Criteria;->setAccuracy(I)V", 0),
    ("Landroid/view/animation/ScaleAnimation;", 0),
    ("Landroid/widget/EditText;", 0),
    ("Landroid/webkit/JsPromptResult;", 0),
    ("Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F", 0),
    ("Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V", 0),
    ("Landroid/content/BroadcastReceiver;-><init>()V", 0),
    ("Landroid/widget/LinearLayout;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V", 0),
    ("Landroid/net/Uri$Builder;->build()Landroid/net/Uri;", 0),
    ("Landroid/app/ActivityManager$RunningTaskInfo;", 0),
    ("Landroid/content/res/TypedArray;->getFloat(IF)F", 0),
    ("Landroid/widget/RelativeLayout;->setBackgroundResource(I)V", 0),
    ("Landroid/widget/Button;->setTextSize(F)V", 0),
    ("Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V", 0),
    ("Landroid/net/wifi/WifiManager;->isWifiEnabled()Z", 0),
    ("Landroid/webkit/JsPromptResult;->cancel()V", 0),
    ("Landroid/os/Parcel;->createDoubleArray()", 0),
    ("Landroid/app/Notification;->tickerText:Ljava/lang/CharSequence;", 0),
    ("Landroid/app/AlarmManager;", 0),
    ("Landroid/graphics/Point;-><init>()V", 0),
    ("Landroid/graphics/Canvas;->getClipBounds()Landroid/graphics/Rect;", 0),
    ("Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;", 0),
    ("Landroid/content/Intent$ShortcutIconResource;->fromContext(Landroid/content/Context;I)Landroid/content/Intent$ShortcutIconResource;", 0),
    ("Landroid/webkit/WebChromeClient;->onProgressChanged(Landroid/webkit/WebView;I)V", 0),
    ("Landroid/webkit/WebChromeClient;->onJsPrompt(Landroid/webkit/WebView;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/webkit/JsPromptResult;)Z", 0),
    ("Landroid/widget/ImageButton;->setPadding(IIII)V", 0),
    ("Landroid/widget/VideoView;->stopPlayback()V", 0),
    ("Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V", 0),
    ("Landroid/widget/Button;->setPadding(IIII)V", 0),
    ("Landroid/database/CursorWindow;->getNumRows()I", 0),
    ("Landroid/widget/Gallery;", 0),
    ("Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;", 0),
    ("Landroid/os/Handler;->handleMessage(Landroid/os/Message;)V", 0)
  )
}
