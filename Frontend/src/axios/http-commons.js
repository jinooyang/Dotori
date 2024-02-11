import axios from "axios";
// import { httpStatusCode } from "./http-status";


function localAxios() {
  const instance = axios.create({
    baseURL: 'http://localhost:8080',
    withCredentials: true,
    headers: {
      "Content-Type": "application/json;charset=utf-8",
    },
  });
  // instance.defaults.headers.post["withCredentials"] = true;
  // instance.defaults.headers.get["withCredentials"] = true;
  // instance.defaults.headers.delete["withCredentials"] = true;
  instance.defaults.headers.post["Content-Type"] = "application/json";
  instance.defaults.headers.get["Content-Type"] = "application/json";
  instance.defaults.headers.delete["Content-Type"] = "application/json";
  // instance.defaults.headers.put["Content-Type"] = "application/json";
  return instance;
}
export { localAxios };
