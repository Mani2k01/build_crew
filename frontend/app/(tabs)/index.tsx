import React, { useRef } from "react";
import { SafeAreaView, Button, View } from "react-native";
import { WebView } from "react-native-webview";

export default function DoctorPortal() {
  const webRef = useRef<WebView>(null);

  const reloadPage = () => {
    webRef.current?.reload();
  };

  return (
    <SafeAreaView style={{ flex: 1 }}>

      <WebView
        ref={webRef}
        source={{ uri: "http://10.213.103.16:3000/" }}
        javaScriptEnabled
        domStorageEnabled
        startInLoadingState
        pullToRefreshEnabled={true}
      />
    </SafeAreaView>
  );
}
