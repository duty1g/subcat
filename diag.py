print("Testing requests...")
try:
    import requests
    print("requests OK:", requests.__file__)
except ImportError as e:
    print("requests FAIL:", e)
except Exception as e:
    print("requests ERR:", e)

print("\nTesting smart_requests...")
try:
    import smart_requests
    print("smart_requests OK:", smart_requests.__file__)
except ImportError as e:
    print("smart_requests FAIL:", e)
except Exception as e:
    print("smart_requests ERR:", e)

print("\nTesting google.generativeai...")
try:
    import google.generativeai
    print("google.generativeai OK")
except ImportError as e:
    print("google.generativeai FAIL:", e)
except Exception as e:
    print("google.generativeai ERR:", e)
