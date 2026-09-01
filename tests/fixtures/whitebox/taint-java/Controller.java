class Controller {
  void unsafe(Request request) throws Exception {
    String value = request.getParameter("url");
    new java.net.URL(value).openConnection();
  }
  void safe(Request request) throws Exception {
    String value = request.getParameter("url");
    String checked = validate(value);
    new java.net.URL(checked).openConnection();
  }
}
