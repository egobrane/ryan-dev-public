using System;
namespace Wizards_and_Warriors;

public class WizardsAndWarriors
{
    static void Main(string[] args)
    {
        var warrior = new Warrior();
        warrior.ToString();
        warrior.Vulnerable();
        // => false
        var wizard = new Wizard();
        wizard.Vulnerable();
        // => true
        wizard.PrepareSpell();
        wizard.Vulnerable();
        // => false
        wizard.DamagePoints(warrior);
        // => 12
    }
}

public abstract class Character
{
    public string? characterType { get; }
    protected Character(string characterType) => this.characterType = characterType;
    public abstract int DamagePoints(Character target);
    public virtual bool Vulnerable() => false;
    public override string ToString() => $"Character is a {characterType}";
}

public class Warrior : Character
{
    public Warrior() : base("Warrior") { }
    public override int DamagePoints(Character target) => (target.Vulnerable() ? 10 : 6);
}

public class Wizard : Character
{
    public Wizard() : base("Wizard") { }
    public bool spellPrepared = false;
    public override int DamagePoints(Character target) => (spellPrepared ? 12 : 3);
    public override bool Vulnerable() => (!spellPrepared);
    public void PrepareSpell() => spellPrepared = true;
}

