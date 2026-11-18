import keras


def restore(path):
    return keras.models.load_model(path)
