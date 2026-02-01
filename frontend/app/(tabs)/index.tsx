import React from "react";
import { SafeAreaView } from "react-native";
import { WebView } from "react-native-webview";

export default function App() {
  return (
    <SafeAreaView style={{ flex: 1 }}>
      <WebView
        source={{ uri: "https://build-crew.onrender.com" }}
        style={{ flex: 1 }}
      />
    </SafeAreaView>
  );
}