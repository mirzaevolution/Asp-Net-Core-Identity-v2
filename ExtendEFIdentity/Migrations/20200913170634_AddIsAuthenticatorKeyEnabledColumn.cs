using Microsoft.EntityFrameworkCore.Migrations;

namespace ExtendEFIdentity.Migrations
{
    public partial class AddIsAuthenticatorKeyEnabledColumn : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsAuthenticatorKeyEnabled",
                table: "AspNetUsers",
                nullable: false,
                defaultValue: false);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsAuthenticatorKeyEnabled",
                table: "AspNetUsers");
        }
    }
}
