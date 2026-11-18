import keras


def build():
    model = keras.Sequential([keras.layers.Dense(1)])
    model.compile(optimizer="sgd", loss="mse")
    return model
