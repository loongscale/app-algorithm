import numpy as np
def ease_out_quart(x):
    return 1 - pow(1 - x, 4)
def get_tracks(distance, seconds, ease_func):
    """
    根据轨迹离散分布数学模型生成滑动轨迹
    """
    distance += 20
    tracks = [0]
    offsets = [0]
    for t in np.arange(0.0, seconds, 0.1):
        ease = ease_func
        offset = round(ease(t / seconds) * distance)
        tracks.append(offset - offsets[-1])
        offsets.append(offset)
    tracks.extend([-3, -2, -3, -2, -2, -2, -2, -1, -0, -1, -1, -1])
    return tracks

print(get_tracks(500, 1, ease_out_quart))