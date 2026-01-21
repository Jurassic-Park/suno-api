import jsdom from "jsdom";
const { JSDOM } = jsdom;

const options = {
    url: "https://suno.com",
    runScripts: "dangerously",
    resources: "usable",
    // beforeParse(window) {
    //     window.alert = () => { };
    //     window.navigator = { userAgent: "Mozilla/5.0" };
    // }
};

JSDOM.fromFile("src/hcp/hcp.html", options).then((dom) => {
    console.log(dom.Gi);
});