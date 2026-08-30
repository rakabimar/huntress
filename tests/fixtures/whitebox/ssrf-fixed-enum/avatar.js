const HOSTS = { small: "https://images.example.test/small.png" };

function fetchAvatar(size) {
  if (!Object.hasOwn(HOSTS, size)) throw new Error("invalid size");
  return httpClient.get(HOSTS[size]);
}
