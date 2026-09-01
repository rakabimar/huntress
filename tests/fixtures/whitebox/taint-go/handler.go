package fixture

func unsafe(r *http.Request) {
	value := r.URL.Query().Get("url")
	http.Get(value)
}

func safe(r *http.Request) {
	value := r.URL.Query().Get("url")
	checked := validate(value)
	http.Get(checked)
}
