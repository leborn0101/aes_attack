# 同步攻击分析
import tworoundattack.utils as utils
import matplotlib.pyplot as plt
import click

from tworoundattack import asynutils


def _doaesattack2(first4bits):
    if len(first4bits) == 0:
        # 若直接进行第二轮攻击，则假设第一轮攻击获取到的秘钥每个字节的前4位如下所示
        frresult = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]
    else:
        frresult = first4bits
    result0_5_10_15 = utils.getsecondroundmeasurementscore0_5_10_15(frresult)
    result1_6_11_12 = utils.getsecondroundmeasurementscore1_6_11_12(frresult)
    result2_7_8_13 = utils.getsecondroundmeasurementscore2_7_8_13(frresult)
    result3_4_9_14 = utils.getsecondroundmeasurementscore3_4_9_14(frresult)
    utils.getresult(result0_5_10_15, result1_6_11_12, result2_7_8_13, result3_4_9_14)


def _doaesattack2_nks(first4bits):
    if len(first4bits) == 0:
        # 若直接进行第二轮攻击，则假设第一轮攻击获取到的秘钥每个字节的前4位如下所示
        frresult = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]
    else:
        frresult = first4bits
    result0_5_10_15 = utils.getsecondroundmeasurementscore0_5_10_15_nks(frresult)
    result1_6_11_12 = utils.getsecondroundmeasurementscore1_6_11_12_nks(frresult)
    result2_7_8_13 = utils.getsecondroundmeasurementscore2_7_8_13_nks(frresult)
    result3_4_9_14 = utils.getsecondroundmeasurementscore3_4_9_14_nks(frresult)
    utils.getresult_nks(result0_5_10_15, result1_6_11_12, result2_7_8_13, result3_4_9_14)


# 第一轮攻击，获取秘钥每个字节的前4位，通过图表柱状图表示出来，命令行参数path表示待分析数据所在目录
@click.command()
@click.option('-p', '--path', required=True)
def doaesattack1(path):
    utils.myinit(path)
    result = utils.getfirstroundmeasurementscorebycache()
    for i in range(16):
        mmin = min(result[i])
        plt.subplot(4, 4, 1 + i)
        plt.bar(range(len(result[i])), result[i] - mmin, bottom=mmin)
    pt = path + "/result"
    with open(pt, "w") as f:
        for i in range(16):
            for j in range(16):
                s = "%f " % result[i][j]
                f.write(s)
            f.write("\n")
    plt.show()


# 第一轮攻击，获取秘钥每个字节的前4位，通过图表柱状图表示出来，命令行参数path表示待分析数据所在目录
@click.command()
@click.option('-p', '--path', required=True)
def doaesattack1_nks(path):
    utils.myinit(path)
    result = utils.getfirstroundmeasurementscorebycache_nks()
    for i in range(16):
        mmin = min(result[i])
        plt.subplot(4, 4, 1 + i)
        plt.bar(range(len(result[i])), result[i] - mmin, bottom=mmin)
    pt = path + "/result_nks"
    with open(pt, "w") as f:
        for i in range(16):
            for j in range(16):
                s = "%f " % result[i][j]
                f.write(s)
            f.write("\n")
    plt.show()


# 第二轮攻击，获取秘钥每个字节的后4位，并将结果写到path所在目录下，path的含义同上方法，该方法假设第一轮获取到正确的秘钥字节前4位
@click.command()
@click.option('-p', '--path', required=True)
def doaesattack2(path):
    utils.myinit(path)
    _doaesattack2([])


# 第二轮攻击，获取秘钥每个字节的后4位，并将结果写到path所在目录下，path的含义同上方法，该方法假设第一轮获取到正确的秘钥字节前4位
@click.command()
@click.option('-p', '--path', required=True)
def doaesattack2_nks(path):
    utils.myinit(path)
    _doaesattack2_nks([])


# 首先进行第一轮攻击获取到秘钥字节前4位，利用第一轮攻击的结果进行第二轮攻击获取秘钥字节的后4位，最终得到完整的AES秘钥
@click.command()
@click.option('-p', '--path', required=True)
def attack(path):
    utils.myinit(path)
    frr = utils.getfirstroundmeasurementscorebycache()
    f4b = utils.getfirst4bits(frr)
    _doaesattack2(f4b)


# 首先进行第一轮攻击获取到秘钥字节前4位，利用第一轮攻击的结果进行第二轮攻击获取秘钥字节的后4位，最终得到完整的AES秘钥
@click.command()
@click.option('-p', '--path', required=True)
def attack_nks(path):
    utils.myinit(path)
    frr = utils.getfirstroundmeasurementscorebycache_nks()
    f4b = utils.getfirst4bits(frr)
    _doaesattack2_nks(f4b)


# 异步攻击分析，path表示异步分析数据所在文件夹路径，base为aes table首地址映射到cache中的set索引i
@click.command()
@click.option('-p', '--path', required=True)
@click.option('-b', '--base', required=True)
def asynattack(path, base):
    asynutils.doasynattack(path, base)


# 同上，不过probe测量得到的时间没有减去基础时间
@click.command()
@click.option('-p', '--path', required=True)
def asynattacknobase(path):
    asynutils.doasynattacknobase(path)


@click.group()
def cli():
    pass


cli.add_command(attack)
cli.add_command(doaesattack1)
cli.add_command(doaesattack2)
cli.add_command(attack_nks)
cli.add_command(doaesattack1_nks)
cli.add_command(doaesattack2_nks)
cli.add_command(asynattack)
cli.add_command(asynattacknobase)


def main():
    cli(obj={})


if __name__ == '__main__':
    main()